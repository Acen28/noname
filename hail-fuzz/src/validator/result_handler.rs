//! Handle Validator results

use crate::validator::{ValidationResult, ValidatorManager, ValidatorTask};
use hashbrown::HashMap;
use std::sync::{mpsc, Arc};

pub fn handle_validator_results(
    rx: mpsc::Receiver<(ValidatorTask, ValidationResult)>,
    manager: Arc<ValidatorManager>,
    validated_crashes: Arc<std::sync::Mutex<std::collections::HashSet<(u64, u64)>>>,
    _learned_edges: Option<Arc<std::sync::Mutex<HashMap<u64, Vec<u64>>>>>, 
    while let Ok((task, result)) = rx.recv() {
        match result {
            ValidationResult::TrueCrash => {
                eprintln!(
                    "[Validator] Confirmed True Crash for input {} (0x{:x} -> 0x{:x})",
                    task.crash_input_id, task.last_addr, task.current_addr
                );
                if let Ok(mut validated) = validated_crashes.lock() {
                    validated.insert((task.last_addr, task.current_addr));
                }
            }
            ValidationResult::ValidJump(targets) => {
                eprintln!(
                    "[Validator] Valid jump targets for input {}: {:?}",
                    task.crash_input_id, targets
                );

                match manager.learned_edges.lock() {
                    Ok(guard) => {
                        if let Some(ref learned_edges_arc) = *guard {
                            if let Ok(mut edges) = learned_edges_arc.lock() {
                                edges
                                    .entry(task.current_addr)
                                    .or_insert_with(Vec::new)
                                    .push(task.last_addr);

                                for target in targets {
                                    edges
                                        .entry(target)
                                        .or_insert_with(Vec::new)
                                        .push(task.last_addr);
                                }

                                eprintln!(
                                    "[Validator] ✓ Added valid jump edge(s) to CFG: 0x{:x} -> 0x{:x}",
                                    task.last_addr, task.current_addr
                                );
                            }
                        } else {
                            eprintln!(
                                "[Validator] ⚠️ learned_edges not set in ValidatorManager, cannot update CFG"
                            );
                        }
                    }
                    Err(_) => {
                        eprintln!("[Validator] ⚠️ Failed to lock learned_edges, cannot update CFG");
                    }
                }
            }
            ValidationResult::Unknown => {
                eprintln!(
                    "[Validator] Unable to determine for input {} (0x{:x} -> 0x{:x})",
                    task.crash_input_id, task.last_addr, task.current_addr
                );
            }
        }
    }
}
