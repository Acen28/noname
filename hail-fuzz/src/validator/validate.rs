//! Validator core logic: REPLAY with taint tracking and call Angr

use super::ValidationResult; // ValidationResult is defined in parent module (mod.rs)
use crate::validator::path_checker::ReplayPathChecker;
use crate::validator::python_service::PythonService;
use crate::validator::TaintTracker;
use crate::validator::ValidatorTask;
use crate::{Fuzzer, Snapshot, VmExit};
use anyhow::Context;
use hashbrown::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub fn validate_crash_with_fuzzer(
    mut fuzzer: Fuzzer,
    task: &ValidatorTask,
    python_service: &Arc<Mutex<Option<PythonService>>>,
) -> anyhow::Result<ValidationResult> {
    let taint_tracker = Arc::new(Mutex::new(TaintTracker::new()));

    Snapshot::restore_initial(&mut fuzzer);

    fuzzer.state.input.clone_from(&task.crash_input);
    fuzzer
        .state
        .input
        .set_taint_tracker(Some(taint_tracker.clone()));

    fuzzer.state.input.seek_to_start(); 
    fuzzer
        .write_input_to_target()
        .context("Failed to write input to target")?;

    let mmio_handler = fuzzer
        .target
        .get_mmio_handler(&mut fuzzer.vm)
        .ok_or_else(|| anyhow::format_err!("target does not support MultiStream input"))?;

    mmio_handler.seek_to_start();

    let total_bytes: usize = mmio_handler.streams.values().map(|s| s.bytes.len()).sum();
    if mmio_handler.streams.is_empty() {
        anyhow::bail!("MMIO handler has no input streams after write_input_to_target! This will cause replay divergence.");
    }
    if total_bytes == 0 {
        anyhow::bail!("MMIO handler has empty input streams after write_input_to_target! This will cause replay divergence.");
    }

    let non_zero_cursors: Vec<_> = mmio_handler
        .streams
        .iter()
        .filter(|(_, stream)| stream.cursor != 0)
        .map(|(k, s)| (*k, s.cursor))
        .collect();
    if !non_zero_cursors.is_empty() {
        eprintln!(
            "[Validator] ⚠️ WARNING: Some MMIO handler streams have non-zero cursors: {:?}",
            non_zero_cursors
        );
        mmio_handler.seek_to_start();
        eprintln!("[Validator] 🔧 Reset all cursors to 0");
    }

    let target_pc = task.last_addr;

    let cold_start_execs = crate::config::cold_start_execs();
    let enable_path_checker = if let Some(ref cfi_hook) = fuzzer.cfi_hook {
        if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
            let current_execs = cfi.current_execs.load(std::sync::atomic::Ordering::Relaxed);
            cold_start_execs == 0 || current_execs >= cold_start_execs
        } else {
            false
        }
    } else {
        false
    };

    let (_hook_id, suspicious_jumps) = if enable_path_checker {
        let (cfg_data, block_metadata, isr_whitelist_snapshot, text_range, learned_edges_snapshot) =
            if let Some(ref cfi_hook) = fuzzer.cfi_hook {
                if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
                    let learned_snapshot = if let Ok(guard) = cfi.global_learned_edges.try_lock() {
                        Some(guard.clone()) 
                    } else {
                        Some(HashMap::new())
                    };

                    let isr_snapshot = if let Some(ref isr_arc) = cfi.isr_whitelist {
                        if let Ok(guard) = isr_arc.try_lock() {
                            Some(guard.clone()) 
                        } else {
                            Some(HashSet::new())
                        }
                    } else {
                        None
                    };

                    (
                        cfi.cfg_data.clone(),       
                        cfi.block_metadata.clone(), 
                        isr_snapshot.map(|snapshot| Arc::new(Mutex::new(snapshot))), 
                        cfi.text_range,
                        learned_snapshot.map(|snapshot| Arc::new(Mutex::new(snapshot))), 
                    )
                } else {
                    (None, None, None, None, None)
                }
            } else {
                (None, None, None, None, None)
            };

        let path_checker = ReplayPathChecker::new(
            cfg_data,
            block_metadata,
            isr_whitelist_snapshot, 
            text_range,
            taint_tracker.clone(),
            learned_edges_snapshot, 
        );

        let hook_id = fuzzer.vm.cpu.add_hook(path_checker);
        icicle_vm::injector::register_block_hook_injector(&mut fuzzer.vm, 0, u64::MAX, hook_id);

        let _exit = execute_until_pc(&mut fuzzer, target_pc)
            .context("Failed to execute to last_addr (jump source)")?;

        let suspicious_jumps = {
            if let Some(path_checker_data) = fuzzer
                .vm
                .cpu
                .get_hook_mut(hook_id)
                .data_mut::<ReplayPathChecker>()
            {
                let jumps = path_checker_data.get_suspicious_jumps().to_vec();
                if path_checker_data.has_suspicious_jumps() {
                    use hashbrown::HashSet;
                    let mut seen = HashSet::new();
                    let mut unique_jumps = Vec::new();

                    for jump in &jumps {
                        let key = (jump.last_addr, jump.current_addr);
                        if seen.insert(key) {
                            unique_jumps.push(jump);
                        }
                    }
                }
                jumps
            } else {
                Vec::new()
            }
        };

        (Some(hook_id), suspicious_jumps)
    } else {
        let _exit = execute_until_pc(&mut fuzzer, target_pc)
            .context("Failed to execute to last_addr (jump source)")?;
        (None, Vec::new()) 
    };

    if !suspicious_jumps.is_empty() {
        eprintln!("[Validator] ☠️ SILENT CRASH detected: Intermediate PC corruption during replay");
        return Ok(ValidationResult::TrueCrash);
    }

    let final_pc = fuzzer.vm.cpu.read_pc();

    if final_pc != target_pc && (final_pc & !1) != (target_pc & !1) {
        eprintln!(
            "[Validator] ⚠️ WARNING: PC mismatch! Expected 0x{:x}, got 0x{:x}",
            target_pc, final_pc
        );
        eprintln!("[Validator] This may cause Angr to start from wrong address!");
        eprintln!("[Validator] Possible causes: replay divergence or MMIO handler mismatch");
        eprintln!(
            "[Validator] 🔧 Force setting PC to target_pc: 0x{:x}",
            target_pc
        );
        fuzzer.vm.cpu.write_pc(target_pc);
    }

    if let Ok(mut tracker) = taint_tracker.lock() {
        tracker.update_icount(fuzzer.vm.cpu.icount());
    }

    let dump_dir = task
        .workdir
        .join("validator_dumps")
        .join(format!("{}", task.crash_input_id));


    crate::validator::dump::dump_vm_state_for_angr_with_tracker(
        &mut fuzzer,
        &dump_dir,
        Some(&taint_tracker.lock().unwrap()),
    )
    .context("Failed to dump VM state")?;

    let python_service_guard = python_service.lock().unwrap();
    if let Some(ref service) = *python_service_guard {

        match service.validate(&dump_dir, task.current_addr, task.last_addr) {
            Ok(response) => {
                match response.result_type.as_str() {
                    "TrueCrash" => {
                        eprintln!("[Validator] Confirmed True Crash");
                        return Ok(ValidationResult::TrueCrash);
                    }
                    "ValidJump" => {
                        eprintln!("[Validator] Valid jump targets: {:?}", response.targets);
                        return Ok(ValidationResult::ValidJump(response.targets));
                    }
                    _ => {
                        eprintln!("[Validator] Unknown result type: {}", response.result_type);
                        if let Some(ref err) = response.error {
                            eprintln!("[Validator] 🛑 Python Error Detail: {}", err);

                            if err.contains("timeout") {
                                eprintln!("[Validator] ⏰ Timeout detected, treating as ValidJump (empty targets)");
                                return Ok(ValidationResult::ValidJump(vec![]));
                            }
                        }
                        return Ok(ValidationResult::Unknown);
                    }
                }
            }
            Err(e) => {
                eprintln!("[Validator] Python service error: {}", e);
                return Ok(ValidationResult::Unknown);
            }
        }
    } else {
        eprintln!("[Validator] Python service is not available");
        return Ok(ValidationResult::Unknown);
    }
}

fn execute_until_pc(fuzzer: &mut Fuzzer, target_pc: u64) -> anyhow::Result<VmExit> {
    fuzzer.vm.add_breakpoint(target_pc);

    let max_instructions = 10_000_000;
    let old_limit = fuzzer.vm.icount_limit;
    fuzzer.vm.icount_limit = max_instructions;

    let start_icount = fuzzer.vm.cpu.icount();
    let mut last_log_icount = start_icount;
    let log_interval = 1_000_000; 

    let exit = loop {
        let current_icount = fuzzer.vm.cpu.icount();

        if current_icount - last_log_icount >= log_interval {
            eprintln!(
                "[Validator] Progress: {}M instructions executed (target: 0x{:x})",
                (current_icount - start_icount) / 1_000_000,
                target_pc
            );
            last_log_icount = current_icount;
        }

        match fuzzer.execute() {
            Some(VmExit::Breakpoint) => {

                let current_pc = fuzzer.vm.cpu.read_pc();

                if current_pc == target_pc || (current_pc & !1) == (target_pc & !1) {
                    break Some(VmExit::Breakpoint);
                } else {
                    eprintln!("[Validator] ⚠️ Breakpoint hit but PC mismatch! Expected: 0x{:x}, Got: 0x{:x}", 
                        target_pc, current_pc);
                    eprintln!(
                        "[Validator] This indicates replay divergence. Attempting to continue..."
                    );
                    if current_pc > target_pc && current_pc <= target_pc + 4 {
                        eprintln!("[Validator] 🔧 PC is next instruction, adjusting to target_pc");
                        fuzzer.vm.cpu.write_pc(target_pc);
                        break Some(VmExit::Breakpoint);
                    } else {
                        fuzzer.vm.icount_limit = old_limit;
                        fuzzer.vm.remove_breakpoint(target_pc);
                        anyhow::bail!(
                            "Replay diverged! Expected PC: 0x{:x}, Got: 0x{:x}",
                            target_pc,
                            current_pc
                        );
                    }
                }
            }
            Some(exit) if !matches!(exit, VmExit::Running) => {
                break Some(exit);
            }
            Some(_) => {
                continue;
            }
            None => {
                let current_pc = fuzzer.vm.cpu.read_pc();
                if current_pc == target_pc || (current_pc & !1) == (target_pc & !1) {
                    break Some(VmExit::Breakpoint);
                }
                continue;
            }
        }
    };

    fuzzer.vm.icount_limit = old_limit;

    fuzzer.vm.remove_breakpoint(target_pc);

    exit.ok_or_else(|| anyhow::anyhow!("Failed to reach target PC: 0x{:x}", target_pc))
}
