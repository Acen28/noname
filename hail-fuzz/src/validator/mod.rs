//! Validator module for validating Potential Crashes using DSE (Dynamic Symbolic Execution)
//!
//! This module implements a validator that runs in a separate thread to avoid impacting
//! the main fuzzing performance. It uses taint tracking during REPLAY and Angr for DSE.

mod dump;
mod path_checker;
mod python_service;
mod result_handler;
mod taint;
mod taint_mmio;
mod validate;

pub use taint::TaintTracker;

use crate::{queue::InputId, Config, MultiStream};
use hashbrown::{HashMap, HashSet};
use std::{
    io::Write,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn append_validator_queue_row(workdir: &PathBuf, row: &str) {
    let path = workdir.join("validator_queue.csv");
    let needs_header = !path.exists();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        if needs_header {
            let _ = file.write_all(
                b"enqueue_ms,dequeue_ms,finish_ms,queue_wait_ms,process_ms,e2e_ms,queue_len_at_enqueue,last_addr,current_addr,input_id,result,zombie\n",
            );
        }
        let _ = file.write_all(row.as_bytes());
    }
}

struct QueuedTask {
    task: ValidatorTask,
    enqueue_ms: u64,
    queue_len_at_enqueue: usize,
}

#[derive(Clone)]
pub struct ValidatorTask {
    pub crash_input: MultiStream,
    pub crash_input_id: InputId,
    pub last_addr: u64,
    pub current_addr: u64,
    pub workdir: PathBuf,
}

impl ValidatorTask {
    pub fn key(&self) -> (u64, u64) {
        (self.last_addr, self.current_addr)
    }
}

#[derive(Debug, Clone)]
pub enum ValidationResult {
    TrueCrash,
    ValidJump(Vec<u64>),
    Unknown,
}

pub struct ValidatorManager {
    task_queue: Arc<Mutex<Vec<QueuedTask>>>,
    result_sender: Arc<Mutex<mpsc::Sender<(ValidatorTask, ValidationResult)>>>,
    config: Config,
    python_service: Arc<Mutex<Option<python_service::PythonService>>>,
    seen_tasks: Arc<Mutex<HashSet<(u64, u64)>>>,
    learned_edges: Arc<Mutex<Option<Arc<Mutex<HashMap<u64, Vec<u64>>>>>>>,
    disabled_seeds: Arc<Mutex<HashSet<InputId>>>,
    pub tasks_enqueued: Arc<std::sync::atomic::AtomicU64>,
}

impl ValidatorManager {
    pub fn new(config: Config, tx: mpsc::Sender<(ValidatorTask, ValidationResult)>) -> Self {
        Self {
            task_queue: Arc::new(Mutex::new(Vec::new())),
            result_sender: Arc::new(Mutex::new(tx)), 
            config,
            python_service: Arc::new(Mutex::new(None)),
            seen_tasks: Arc::new(Mutex::new(HashSet::new())),
            learned_edges: Arc::new(Mutex::new(None)),
            disabled_seeds: Arc::new(Mutex::new(HashSet::new())),
            tasks_enqueued: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn set_learned_edges(&self, learned_edges: Arc<Mutex<HashMap<u64, Vec<u64>>>>) {
        *self.learned_edges.lock().unwrap() = Some(learned_edges);
    }

    pub fn get_disabled_seeds(&self) -> Arc<Mutex<HashSet<InputId>>> {
        self.disabled_seeds.clone()
    }

    pub fn mark_seed_disabled(&self, seed_id: InputId) {
        if let Ok(mut disabled) = self.disabled_seeds.lock() {
            disabled.insert(seed_id);
        }
    }

    pub fn mark_seeds_disabled(&self, seed_ids: &[InputId]) {
        if let Ok(mut disabled) = self.disabled_seeds.lock() {
            for &id in seed_ids {
                disabled.insert(id);
            }
        }
    }

    pub fn get_learned_edges(&self) -> Arc<Mutex<Option<Arc<Mutex<HashMap<u64, Vec<u64>>>>>>> {
        self.learned_edges.clone()
    }

    pub fn start(&self) -> anyhow::Result<()> {
        let workdir = self.config.workdir.clone();
        let python_service = python_service::PythonService::start(&workdir)?;
        *self.python_service.lock().unwrap() = Some(python_service);

        let task_queue = self.task_queue.clone();
        let result_sender = self.result_sender.clone();
        let config = self.config.clone();
        let python_service = self.python_service.clone();
        let disabled_seeds = self.disabled_seeds.clone();

        thread::Builder::new()
            .name("validator".to_string())
            .spawn(move || {
                validator_thread_loop(
                    task_queue,
                    result_sender,
                    config,
                    python_service,
                    disabled_seeds,
                );
            })?;

        eprintln!("[Validator] Validator thread started");
        Ok(())
    }

    pub fn add_task(&self, task: ValidatorTask) {
        let key = task.key();
        let mut seen = self.seen_tasks.lock().unwrap();

        if seen.contains(&key) {
            return;
        }

        seen.insert(key);
        drop(seen);

        let enqueue_ms = wall_clock_ms();
        let mut queue = self.task_queue.lock().unwrap();
        let queue_len_at_enqueue = queue.len();
        queue.push(QueuedTask {
            task,
            enqueue_ms,
            queue_len_at_enqueue,
        });
        drop(queue);
        self.tasks_enqueued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn validator_thread_loop(
    task_queue: Arc<Mutex<Vec<QueuedTask>>>,
    result_sender: Arc<Mutex<mpsc::Sender<(ValidatorTask, ValidationResult)>>>,
    config: Config,
    python_service: Arc<Mutex<Option<python_service::PythonService>>>,
    disabled_seeds: Arc<Mutex<HashSet<InputId>>>,
) {
    loop {
        let queued = {
            let mut queue = task_queue.lock().unwrap();
            queue.pop()
        };

        if let Some(QueuedTask {
            task,
            enqueue_ms,
            queue_len_at_enqueue,
        }) = queued
        {
            let dequeue_ms = wall_clock_ms();
            let is_zombie = {
                if let Ok(disabled) = disabled_seeds.lock() {
                    disabled.contains(&task.crash_input_id)
                } else {
                    false
                }
            };

            let (result, zombie) = if is_zombie {
                eprintln!(
                    "[Validator] 🧟 Skipping zombie task: input {} (0x{:x} -> 0x{:x}) has been disabled while queued",
                    task.crash_input_id, task.last_addr, task.current_addr
                );
                (ValidationResult::Unknown, true)
            } else {
                eprintln!(
                    "[Validator] Processing crash: 0x{:x} -> 0x{:x}",
                    task.last_addr, task.current_addr
                );
                let config_clone = config.clone();
                let result = match create_validator_fuzzer(config_clone) {
                    Ok(fuzzer) => {
                        match crate::validator::validate::validate_crash_with_fuzzer(
                            fuzzer,
                            &task,
                            &python_service,
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("[Validator] Validation error: {}", e);
                                ValidationResult::Unknown
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[Validator] Failed to create fuzzer for validation: {}", e);
                        ValidationResult::Unknown
                    }
                };
                (result, false)
            };

            let finish_ms = wall_clock_ms();
            let queue_wait_ms = dequeue_ms.saturating_sub(enqueue_ms);
            let process_ms = finish_ms.saturating_sub(dequeue_ms);
            let e2e_ms = finish_ms.saturating_sub(enqueue_ms);
            let result_str = match &result {
                ValidationResult::TrueCrash => "TrueCrash",
                ValidationResult::ValidJump(_) => "ValidJump",
                ValidationResult::Unknown => "Unknown",
            };
            append_validator_queue_row(
                &task.workdir,
                &format!(
                    "{},{},{},{},{},{},{},0x{:x},0x{:x},{},{},{}\n",
                    enqueue_ms,
                    dequeue_ms,
                    finish_ms,
                    queue_wait_ms,
                    process_ms,
                    e2e_ms,
                    queue_len_at_enqueue,
                    task.last_addr,
                    task.current_addr,
                    task.crash_input_id,
                    result_str,
                    if zombie { 1 } else { 0 },
                ),
            );

            if let Ok(sender) = result_sender.lock() {
                if let Err(e) = sender.send((task, result)) {
                    eprintln!("[Validator] Failed to send result: {}", e);
                }
            }
        } else {
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn create_validator_fuzzer(config: Config) -> anyhow::Result<crate::Fuzzer> {
    use crate::queue::GlobalQueue;
    use crate::queue::GlobalRef;
    use std::sync::Arc;

    let global_queue = Arc::new(GlobalQueue::init(1));
    let global = GlobalRef::new(0, global_queue, None);

    crate::Fuzzer::new(config, global)
}
