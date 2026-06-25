use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Context;
use hashbrown::{hash_map::Entry, HashMap};
use icicle_fuzzing::CrashKind;
use icicle_vm::{Vm, VmExit};

use crate::{
    cfi::CfiCrashType,
    dictionary::DictionaryItem,
    input::{CortexmMultiStream, StreamKey},
    queue::InputId,
    Fuzzer, Stage, State,
};

#[derive(Copy, Clone)]
pub(crate) struct Monitor {
    /// The total number of executions that the fuzzer has done
    pub total_executions: u64,

    /// The number of crashes that the fuzzer has seen
    pub crashes: u64,

    /// The number of times a timeout has been hit
    pub timeouts: u64,

    /// The number of unique blocks that the fuzzer has seen with any input
    pub blocks_seen: u64,

    /// An instant that keeps track of when the fuzzer start.
    pub start_time: Instant,

    /// The last time we wrote the stats to a file.
    pub last_log_time: Instant,

    /// The amount of time to wait before writing current stats to a file.
    pub log_rate: Duration,

    /// The time it took to execute the slowest input.
    pub max_duration: Duration,

    /// The maximum number of instructions executed by a single test case.
    pub max_instructions: u64,

    /// The last point in time that we got new coverage
    pub last_coverage_increase: Instant,

    /// The last time that we displayed output.
    pub last_report: Instant,

    /// The total executions the last time we displayed output.
    pub last_exec_count: u64,

    /// The total number of dictionary items the last time we saved the fuzzer dictionary.
    pub last_dict_items: usize,

    /// The ID of the current input.
    pub input_id: usize,

    /// The current stage.
    pub stage: Stage,
}

impl Monitor {
    pub fn new() -> Self {
        let log_rate = match std::env::var("STATS_LOG_RATE") {
            Ok(time) => Duration::from_secs_f64(time.parse::<f64>().unwrap()),
            Err(_) => Duration::from_secs(1),
        };

        Self {
            total_executions: 0,
            crashes: 0,
            timeouts: 0,
            blocks_seen: 0,
            start_time: Instant::now(),
            log_rate,
            last_log_time: Instant::now(),
            last_coverage_increase: Instant::now(),
            last_report: Instant::now(),
            max_duration: Duration::ZERO,
            max_instructions: 0,
            last_exec_count: 0,
            last_dict_items: 0,
            input_id: 0,
            stage: Stage::Import,
        }
    }

    pub fn update(&mut self, fuzzer: &mut Fuzzer) {
        let blocks_seen = fuzzer.vm.code.blocks.len() as u64;
        if blocks_seen != self.blocks_seen {
            self.blocks_seen = blocks_seen;
            self.last_coverage_increase = Instant::now();
        } else {
            // Note: we only update the max time if the number of blocks seen doesn't increase to
            // avoid counting the JIT compilation time.
            self.max_duration = fuzzer.state.exec_time.max(self.max_duration);
        }

        self.max_instructions = fuzzer.state.instructions.max(self.max_instructions);
        self.input_id = fuzzer.input_id.unwrap_or(0);
        self.stage = fuzzer.stage;

        self.log(fuzzer);
    }

    pub fn log(&mut self, fuzzer: &mut Fuzzer) {
        let elapsed_time = self.last_report.elapsed();

        let total_time = self.start_time.elapsed();
        let rate =
            (self.total_executions - self.last_exec_count) as f64 / elapsed_time.as_secs_f64();

        let potential_crash_unique = fuzzer.crash_logger.potential_crashes.len();
        let potential_crash_total: usize = fuzzer
            .crash_logger
            .potential_crashes
            .values()
            .map(|e| e.count)
            .sum();

        let native_crash_unique = fuzzer.crash_logger.native_crashes.len();
        let native_crash_total: usize = fuzzer
            .crash_logger
            .native_crashes
            .values()
            .map(|e| e.count)
            .sum();

        let cfi_violation_unique = fuzzer.crash_logger.cfi_violations.len();
        let cfi_violation_total: usize = fuzzer
            .crash_logger
            .cfi_violations
            .values()
            .map(|e| e.count)
            .sum();

        let validated_crash_unique = fuzzer.crash_logger.validated_crashes.len();
        let validated_crash_total: usize = fuzzer
            .crash_logger
            .validated_crashes
            .values()
            .map(|e| e.count)
            .sum();

        let total_crash_unique =
            native_crash_unique + cfi_violation_unique + validated_crash_unique;
        let total_crash_total = native_crash_total + cfi_violation_total + validated_crash_total;

        let hang_unique = fuzzer.crash_logger.hangs.len();

        eprintln!(
            "[{:6} s] {:6.1}k rate= {:5.0}/s {}:{:<4} potential_crash= {:<6} ({} unq)  total_crashes= {:<6} ({} unq) [native={} ({} unq) cfi={} ({} unq) validated={} ({} unq)]  hang= {:<3} ({} unq)  cov= {:<5} ({:<4} TB)  in= {:<3} ({} new)  cycle= {} (find @{})",
            total_time.as_secs(),
            self.total_executions as f64 / 1000.0,
            rate,
            self.stage.short_name(),
            self.input_id,
            potential_crash_total,
            potential_crash_unique,
            total_crash_total,
            total_crash_unique,
            native_crash_total,
            native_crash_unique,
            cfi_violation_total,
            cfi_violation_unique,
            validated_crash_total,
            validated_crash_unique,
            self.timeouts,
            hang_unique,
            fuzzer.coverage.count(),
            fuzzer.seen_blocks.total_seen(),
            fuzzer.corpus.inputs(),
            fuzzer.queue.new_inputs(),
            fuzzer.queue.cycles,
            fuzzer.queue.found_input_at_cycle
        );

        if let Some(ref cfi_hook) = fuzzer.cfi_hook {
            if std::env::var("CFI_PERF_LOG").is_ok() {
                if let Some(stats) = cfi_hook.get_perf_stats(&mut fuzzer.vm) {
                    let avg_sync_time_us = if stats.sync_calls > 0 {
                        stats.sync_total_time_us / stats.sync_calls
                    } else {
                        0
                    };
                    let lock_failure_rate =
                        if stats.try_lock_successes + stats.try_lock_failures > 0 {
                            (stats.try_lock_failures as f64
                                / (stats.try_lock_successes + stats.try_lock_failures) as f64)
                                * 100.0
                        } else {
                            0.0
                        };

                    let total_hooks = stats.fast_path_hits + stats.slow_path_calls;
                    let fast_path_rate = if total_hooks > 0 {
                        (stats.fast_path_hits as f64 / total_hooks as f64) * 100.0
                    } else {
                        0.0
                    };

                    eprintln!(
                        "[CFI Perf] sync={} (avg={}μs) lock_fail={} ({:.1}%) forced={} buf_max={} buf_cur={} edges={} fast_path={} ({:.1}%) slow_path={}",
                        stats.sync_calls,
                        avg_sync_time_us,
                        stats.try_lock_failures,
                        lock_failure_rate,
                        stats.forced_lock_count,
                        stats.max_buffer_size,
                        stats.current_buffer_size,
                        stats.add_edge_calls,
                        stats.fast_path_hits,
                        fast_path_rate,
                        stats.slow_path_calls
                    );
                }
            }
        }

        if std::env::var("PERF_LOG").is_ok() {
            let perf_snapshot = fuzzer.perf_stats.snapshot();
            eprintln!(
                "[Perf] VM: {} execs (avg={}μs) | Trim: {} (avg={}μs) | Havoc: {} (avg={}μs) | I2S: {} (avg={}μs) | Extend: {} (avg={}μs) | Snapshot: {}μs | Write: {}μs | Coverage: {}μs | Queue: {}μs",
                perf_snapshot.vm_exec_count,
                perf_snapshot.vm_exec_avg_us,
                perf_snapshot.trim_count,
                perf_snapshot.trim_avg_us,
                perf_snapshot.havoc_count,
                perf_snapshot.havoc_avg_us,
                perf_snapshot.i2s_count,
                perf_snapshot.i2s_avg_us,
                perf_snapshot.extend_count,
                perf_snapshot.extend_avg_us,
                perf_snapshot.snapshot_restore_avg_us,
                perf_snapshot.input_write_avg_us,
                perf_snapshot.coverage_check_avg_us,
                perf_snapshot.queue_select_avg_us
            );
        }

        if self.last_log_time.elapsed() > self.log_rate {
            self.last_log_time = Instant::now();
            if let Ok(mut monitor_file) = std::fs::File::options()
                .append(true)
                .create(true)
                .open(fuzzer.workdir.join("stats.csv"))
            {
                let _ = monitor_file.write_all(
                    format!(
                        "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                        total_time.as_millis(),
                        self.total_executions,
                        self.crashes,
                        fuzzer.global.crashes.lock().unwrap().len(),
                        self.timeouts,
                        fuzzer.global.hangs.lock().unwrap().len(),
                        fuzzer.coverage.count(),
                        fuzzer.seen_blocks.total_seen(),
                        fuzzer.corpus.inputs(),
                        fuzzer.corpus.metadata.total_input_bytes,
                        fuzzer.corpus.metadata.total_instructions,
                        fuzzer.dict_items,
                    )
                    .as_bytes(),
                );
            }

            if let Some(ref cfi_hook) = fuzzer.cfi_hook {
                if let Some(guard) = cfi_hook.get_perf_stats(&mut fuzzer.vm) {
                    let guard_path = fuzzer.workdir.join("guard_stats.csv");
                    let needs_header = !guard_path.exists();
                    if let Ok(mut guard_file) = std::fs::File::options()
                        .append(true)
                        .create(true)
                        .open(&guard_path)
                    {
                        if needs_header {
                            let _ = guard_file.write_all(
                                b"time_ms,execs,transitions_observed,bitmap_fastpath_hits,filter_allowed,immediate_violations,suspicious_flagged,slow_path_calls,validator_tasks_enqueued\n",
                            );
                        }
                        let validator_enqueued = fuzzer
                            .validator_manager
                            .as_ref()
                            .map(|m| m.tasks_enqueued.load(std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(0);
                        let _ = guard_file.write_all(
                            format!(
                                "{},{},{},{},{},{},{},{},{}\n",
                                total_time.as_millis(),
                                self.total_executions,
                                guard.transitions_observed,
                                guard.fast_path_hits,
                                guard.filter_allowed,
                                guard.immediate_violations,
                                guard.suspicious_flagged,
                                guard.slow_path_calls,
                                validator_enqueued,
                            )
                            .as_bytes(),
                        );
                    }
                }
            }
        }

        if self.last_dict_items != fuzzer.dict_items {
            self.last_dict_items = fuzzer.dict_items;
            let mut dict: Vec<(StreamKey, Vec<&DictionaryItem>)> = fuzzer
                .dict
                .iter()
                .map(|(addr, x)| (*addr, x.entries.values().collect()))
                .collect();
            dict.sort_by_key(|(addr, _)| *addr);
            let dict = serde_json::ser::to_vec(&dict).unwrap();
            std::fs::write(fuzzer.workdir.join("dict.json"), dict).unwrap();
        }

        self.last_report = Instant::now();
        self.last_exec_count = self.total_executions;
    }

    pub fn sync(&mut self, stats: LocalStats) {
        self.total_executions += stats.execs;
        self.crashes += stats.crashes;
        self.timeouts += stats.timeouts;
    }
}

#[derive(Copy, Clone)]
pub(crate) struct LocalStats {
    /// The total executions the last time stats were synced.
    pub execs: u64,

    /// The number of crashes since last sync.
    pub crashes: u64,

    /// The number of timeouts since last sync.
    pub timeouts: u64,

    /// The last time the fuzzer was syncronized.
    pub last_sync: Instant,
}

impl Default for LocalStats {
    fn default() -> Self {
        Self {
            execs: 0,
            crashes: 0,
            timeouts: 0,
            last_sync: Instant::now(),
        }
    }
}

impl LocalStats {
    pub fn update(&mut self, fuzzer: &mut Fuzzer) {
        self.execs += 1;
        if fuzzer.state.effective_is_crashing {
            self.crashes += 1;
        }
        if fuzzer.state.was_hang() {
            self.timeouts += 1;
        }
        self.maybe_sync(fuzzer);
    }

    pub fn maybe_sync(&mut self, fuzzer: &mut Fuzzer) {
        let elapsed_time = self.last_sync.elapsed();
        if elapsed_time < std::time::Duration::from_secs(1) {
            return;
        }

        let is_main_instance = fuzzer.global.is_main_instance();
        let stats_to_sync = *self;

        let monitor_arc = fuzzer.global.monitor.clone();

        if let Some(ref monitor_mutex) = monitor_arc {
            if let Ok(mut monitor) = monitor_mutex.lock() {
                monitor.sync(stats_to_sync);
            }
        }

        if is_main_instance {
            if let Some(ref monitor_mutex) = monitor_arc {
                if let Ok(mut monitor) = monitor_mutex.lock() {
                    monitor.update(fuzzer);
                }
            }
        }

        *self = Self::default();
    }
}

#[derive(serde::Serialize)]
pub(crate) struct CrashEntry {
    id: usize,
    time: std::time::Duration,
    parent: Option<InputId>,
    count: usize,
    exit: String,
    callstack: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashType {
    Native,
    CfiViolation,
    Validated,
}

pub struct CrashLogger {
    crashes: HashMap<String, CrashEntry>,
    hangs: HashMap<String, CrashEntry>,
    pub potential_crashes: HashMap<String, CrashEntry>,

    pub native_crashes: HashMap<String, CrashEntry>,
    pub cfi_violations: HashMap<String, CrashEntry>,
    pub validated_crashes: HashMap<String, CrashEntry>,

    metadata_path: PathBuf,
    crash_dir: Option<PathBuf>, 
    hang_dir: Option<PathBuf>,
    #[allow(dead_code)]
    potential_crash_dir: Option<PathBuf>,

    native_crash_dir: Option<PathBuf>,
    cfi_violation_dir: Option<PathBuf>,
    validated_crash_dir: Option<PathBuf>,

    save_limit: usize,
    print_crashes: bool,
    start_time: std::time::Instant,
}

impl CrashLogger {
    pub fn new(config: &crate::Config) -> anyhow::Result<Self> {
        let workdir = &config.workdir;
        Ok(Self {
            crashes: HashMap::new(),
            hangs: HashMap::new(),
            potential_crashes: HashMap::new(),

            native_crashes: HashMap::new(),
            cfi_violations: HashMap::new(),
            validated_crashes: HashMap::new(),

            metadata_path: workdir.join("crashes.json"),
            crash_dir: config.fuzzer.save_crashes.then(|| workdir.join("crashes")),
            hang_dir: config.fuzzer.save_hangs.then(|| workdir.join("hangs")),
            potential_crash_dir: None, 

            native_crash_dir: config
                .fuzzer
                .save_crashes
                .then(|| workdir.join("crashes").join("native_crashes")),
            cfi_violation_dir: config
                .fuzzer
                .save_crashes
                .then(|| workdir.join("crashes").join("cfi_violations")),
            validated_crash_dir: config
                .fuzzer
                .save_crashes
                .then(|| workdir.join("crashes").join("validated_crashes")),

            save_limit: std::env::var("SAVE_CRASH_LIMIT")
                .ok()
                .and_then(|x| x.parse().ok())
                .unwrap_or(usize::MAX),
            print_crashes: icicle_fuzzing::parse_bool_env("PRINT_CRASHES")?.unwrap_or(true),
            start_time: std::time::Instant::now(),
        })
    }

    pub fn add_if_new(
        &mut self,
        vm: &mut Vm,
        state: &State,
        text_range: Option<(u64, u64)>,
        crash_type: Option<CrashType>, 
    ) -> Option<String> {
        let dst = match CrashKind::from(state.exit) {
            CrashKind::Halt => return None,
            CrashKind::Hang => &mut self.hangs,
            _ => {
                match crash_type {
                    Some(CrashType::Native) => &mut self.native_crashes,
                    Some(CrashType::CfiViolation) => &mut self.cfi_violations,
                    Some(CrashType::Validated) => &mut self.validated_crashes,
                    None => &mut self.crashes, 
                }
            }
        };

        let id = dst.len();

        let key = match state.exit {
            VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::ExecViolation, _))
            | VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::ReadUnmapped, _))
            | VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::WriteUnmapped, _))
            | VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::InvalidInstruction, _))
            | VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::SelfModifyingCode, _)) => {
                let callstack = vm.get_debug_callstack();

                let source_pc = if let Some((text_base, text_end)) = text_range {
                    callstack
                        .iter()
                        .copied()
                        .find(|&pc| pc >= text_base && pc < text_end)
                        .unwrap_or(0)
                } else {
                    callstack
                        .iter()
                        .copied()
                        .find(|&pc| {
                            pc > 0 
                                && pc < 0x20000000  
                                && !(0x40000000..0x60000000).contains(&pc)  
                                && !(0xe0000000..0xf0000000).contains(&pc) 
                                && pc < 0xfffff000 
                        })
                        .unwrap_or(0)
                };

                let type_str = match state.exit {
                    VmExit::UnhandledException((
                        icicle_vm::cpu::ExceptionCode::ExecViolation,
                        _,
                    )) => "ExecViolation",
                    VmExit::UnhandledException((
                        icicle_vm::cpu::ExceptionCode::ReadUnmapped,
                        _,
                    )) => "ReadUnmapped",
                    VmExit::UnhandledException((
                        icicle_vm::cpu::ExceptionCode::WriteUnmapped,
                        _,
                    )) => "WriteUnmapped",
                    VmExit::UnhandledException((
                        icicle_vm::cpu::ExceptionCode::InvalidInstruction,
                        _,
                    )) => "InvalidInstruction",
                    VmExit::UnhandledException((
                        icicle_vm::cpu::ExceptionCode::SelfModifyingCode,
                        _,
                    )) => "SelfModifyingCode",
                    _ => "Unknown",
                };

                format!("0x{:x}_{}_Deduplicated", source_pc, type_str)
            }
            _ => {
                icicle_fuzzing::gen_crash_key(vm, state.exit)
            }
        };

        match dst.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().count += 1;
                None
            }
            Entry::Vacant(slot) => {
                let callstack = vm.get_debug_callstack();
                slot.insert(CrashEntry {
                    id,
                    parent: state.parent,
                    time: self.start_time.elapsed(),
                    count: 1,
                    exit: format!("{:?}", state.exit),
                    callstack,
                });
                Some(key)
            }
        }
    }

    pub fn save(
        &mut self,
        state: &State,
        vm: &mut Vm,
        target: &CortexmMultiStream,
        exit: VmExit,
        cfi_crash_info: Option<(u64, u64, Option<CfiCrashType>)>,
        is_validated: bool,
        dedup_key: Option<&str>,
    ) -> anyhow::Result<()> {
        let crash_kind = CrashKind::from(exit);
        let is_cfi_crash = matches!(
            exit,
            VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::Environment, _))
        );

        let save_dir = match crash_kind {
            CrashKind::Hang => {
                self.print_crash_or_hang(vm, target, exit, "hang");
                match self.hangs.len() < self.save_limit {
                    true => self.hang_dir.as_ref(),
                    false => None,
                }
            }
            _ => {
                if is_validated {
                    self.print_crash_or_hang(vm, target, exit, "crash (validated)");
                    match self.validated_crashes.len() < self.save_limit {
                        true => self.validated_crash_dir.as_ref(),
                        false => None,
                    }
                } else if is_cfi_crash && cfi_crash_info.is_some() {
                    self.print_crash_or_hang(vm, target, exit, "crash (CFI violation)");
                    match self.cfi_violations.len() < self.save_limit {
                        true => self.cfi_violation_dir.as_ref(),
                        false => None,
                    }
                } else {
                    self.print_crash_or_hang(vm, target, exit, "crash (native)");
                    match self.native_crashes.len() < self.save_limit {
                        true => self.native_crash_dir.as_ref(),
                        false => None,
                    }
                }
            }
        };

        if let Some(dir) = save_dir {
            let filename = if is_cfi_crash {
                if let Some((last_addr, current_addr, crash_type_opt)) = cfi_crash_info {
                    if is_validated {
                        format!("0x{:x}_0x{:x}_validated", last_addr, current_addr)
                    } else if let Some(crash_type) = crash_type_opt {
                        let type_suffix = match crash_type {
                            CfiCrashType::SoftJumpToISR => "soft_isr",
                            CfiCrashType::ROP => "rop",
                            CfiCrashType::OutOfText => "out_of_text",
                            CfiCrashType::Unaligned => "unaligned",
                        };
                        format!("0x{:x}_0x{:x}_{}", last_addr, current_addr, type_suffix)
                    } else {
                        format!("0x{:x}_0x{:x}_cfi", last_addr, current_addr)
                    }
                } else {
                    icicle_fuzzing::gen_crash_key(vm, exit)
                }
            } else {
                dedup_key
                    .map(str::to_string)
                    .unwrap_or_else(|| icicle_fuzzing::gen_crash_key(vm, exit))
            };

            let path = dir.join(filename);
            std::fs::write(&path, state.input.to_bytes())
                .with_context(|| format!("failed to save to {}", path.display()))?;
        }

        #[derive(serde::Serialize)]
        struct CrashMetadata<'a> {
            crashes: Vec<(&'a String, &'a CrashEntry)>,
            hangs: Vec<(&'a String, &'a CrashEntry)>,
            potential_crashes: Vec<(&'a String, &'a CrashEntry)>,
            native_crashes: Vec<(&'a String, &'a CrashEntry)>,
            cfi_violations: Vec<(&'a String, &'a CrashEntry)>,
            validated_crashes: Vec<(&'a String, &'a CrashEntry)>,
        }
        let mut metadata = CrashMetadata {
            crashes: self.crashes.iter().collect(),
            hangs: self.hangs.iter().collect(),
            potential_crashes: self.potential_crashes.iter().collect(),
            native_crashes: self.native_crashes.iter().collect(),
            cfi_violations: self.cfi_violations.iter().collect(),
            validated_crashes: self.validated_crashes.iter().collect(),
        };
        metadata
            .crashes
            .sort_by_key(|(_, entry)| entry.callstack.last());
        metadata
            .hangs
            .sort_by_key(|(_, entry)| entry.callstack.last());
        metadata
            .potential_crashes
            .sort_by_key(|(_, entry)| entry.callstack.last());
        metadata
            .native_crashes
            .sort_by_key(|(_, entry)| entry.callstack.last());
        metadata
            .cfi_violations
            .sort_by_key(|(_, entry)| entry.callstack.last());
        metadata
            .validated_crashes
            .sort_by_key(|(_, entry)| entry.callstack.last());
        std::fs::write(&self.metadata_path, serde_json::ser::to_vec(&metadata)?)?;

        Ok(())
    }

    pub fn add_potential_crash(
        &mut self,
        vm: &mut Vm,
        state: &State,
        last_addr: u64,
        current_addr: u64,
    ) -> Option<String> {
        let key = format!("potential_{:x}_{:x}", last_addr, current_addr);

        let id = self.potential_crashes.len();

        match self.potential_crashes.entry(key.clone()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().count += 1;
                None
            }
            Entry::Vacant(entry) => {
                let callstack = vm.get_debug_callstack();

                entry.insert(CrashEntry {
                    id,
                    time: self.start_time.elapsed(),
                    parent: state.parent,
                    count: 1,
                    exit: format!(
                        "CFI Potential Crash: 0x{:x} -> 0x{:x}",
                        last_addr, current_addr
                    ),
                    callstack,
                });

                Some(key)
            }
        }
    }

    fn print_crash_or_hang(
        &self,
        vm: &mut Vm,
        target: &CortexmMultiStream,
        exit: VmExit,
        kind: &str,
    ) {
        use icicle_fuzzing::FuzzTarget;

        if self.print_crashes {
            let backtrace = icicle_vm::debug::backtrace(vm);
            let exit = target.exit_string(exit);
            eprintln!("New {kind} ({exit}): \n{backtrace}");
            tracing::error!("New {kind} ({exit}): \n{backtrace}");
        }
    }
}
