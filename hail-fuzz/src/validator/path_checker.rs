use crate::cfg_extraction::{CfgBlockMetadata, CfgData, IsrWhitelist};
use crate::validator::TaintTracker;
use hashbrown::HashMap;
use icicle_vm::cpu::{Cpu, HookHandler};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SuspiciousJump {
    pub last_addr: u64,
    pub current_addr: u64,
    pub reason: String,
}

pub struct ReplayPathChecker {
    cfg_data: Option<Arc<CfgData>>,
    block_metadata: Option<Arc<CfgBlockMetadata>>,
    isr_whitelist: Option<Arc<Mutex<IsrWhitelist>>>,
    text_range: Option<(u64, u64)>,
    _taint_tracker: Arc<Mutex<TaintTracker>>,
    learned_edges: Option<Arc<Mutex<HashMap<u64, Vec<u64>>>>>,
    suspicious_jumps: Vec<SuspiciousJump>,
    last_block: u64,
    enabled: bool,
}

impl ReplayPathChecker {
    pub fn new(
        cfg_data: Option<Arc<CfgData>>,                
        block_metadata: Option<Arc<CfgBlockMetadata>>, 
        isr_whitelist: Option<Arc<Mutex<IsrWhitelist>>>,
        text_range: Option<(u64, u64)>,
        taint_tracker: Arc<Mutex<TaintTracker>>,
        learned_edges: Option<Arc<Mutex<HashMap<u64, Vec<u64>>>>>,
    ) -> Self {
        Self {
            cfg_data,
            block_metadata,
            isr_whitelist,
            text_range,
            _taint_tracker: taint_tracker,
            learned_edges,
            suspicious_jumps: Vec::new(),
            last_block: 0,
            enabled: true,
        }
    }

    fn is_fall_through(&self, last_addr: u64, current_addr: u64) -> bool {
        if let Some(ref metadata_map) = self.block_metadata {
            let last_clean = last_addr & !1;
            let current_clean = current_addr & !1;

            if let Some(metadata) = metadata_map.as_ref().get(&last_clean) {
                let expected_next = metadata.end_pc + 2;

                if current_clean == expected_next && !metadata.has_explicit_branch {
                    return true;
                }
            }
        }
        false
    }

    fn check_jump_legality(&mut self, last_addr: u64, current_addr: u64) -> Option<String> {
        if last_addr == 0 || last_addr == u64::MAX || last_addr == current_addr {
            return None;
        }

        let last_clean = last_addr & !1;
        let current_clean = current_addr & !1;

        if self.is_fall_through(last_addr, current_addr) {
            return None; 
        }

        let in_cfg = if let Some(ref cfg_data) = self.cfg_data {
            if let Some(predecessors) = cfg_data.as_ref().get(&current_clean) {
                if predecessors.iter().any(|(pred, _)| *pred == last_clean) {
                    return None; 
                }
                true 
            } else {
                false 
            }
        } else {
            false
        };

        let in_learned = if let Some(ref learned_edges_arc) = self.learned_edges {
            if let Ok(learned_edges) = learned_edges_arc.try_lock() {
                if let Some(predecessors) = learned_edges.get(&current_clean) {
                    if predecessors.contains(&last_clean) {
                        return None; 
                    }
                    true 
                } else {
                    false 
                }
            } else {
                false 
            }
        } else {
            false 
        };

        let is_isr = if let Some(ref isr_whitelist_arc) = self.isr_whitelist {
            if let Ok(isr_whitelist) = isr_whitelist_arc.try_lock() {
                if isr_whitelist.contains(&current_clean) {
                    return None; 
                }
                false
            } else {
                false
            }
        } else {
            false 
        };

        let mut reason_parts = Vec::new();
        if !in_cfg {
            reason_parts.push("not in CFG");
        } else {
            reason_parts.push("in CFG but last_addr not a predecessor");
        }
        if !in_learned {
            reason_parts.push("not in learned edges");
        } else {
            reason_parts.push("in learned edges but last_addr not a predecessor");
        }
        if !is_isr {
            reason_parts.push("not ISR entry");
        }
        reason_parts.push("not fall-through");

        let fall_through_info = if let Some(ref metadata_map) = self.block_metadata {
            if let Some(metadata) = metadata_map.as_ref().get(&last_clean) {
                let expected_next = metadata.end_pc + 2;
                format!("(fall-through: last=0x{:x} end_pc=0x{:x} expected=0x{:x} current=0x{:x} has_branch={})", 
                    last_clean, metadata.end_pc, expected_next, current_clean, metadata.has_explicit_branch)
            } else {
                format!(
                    "(fall-through: last=0x{:x} not in block_metadata)",
                    last_clean
                )
            }
        } else {
            "(fall-through: block_metadata is None)".to_string()
        };

        Some(format!(
            "{} - {}",
            reason_parts.join(", "),
            fall_through_info
        ))
    }

    pub fn get_suspicious_jumps(&self) -> &[SuspiciousJump] {
        &self.suspicious_jumps
    }

    pub fn has_suspicious_jumps(&self) -> bool {
        !self.suspicious_jumps.is_empty()
    }

    pub fn reset(&mut self) {
        self.suspicious_jumps.clear();
        self.last_block = 0;
    }
}

impl HookHandler for ReplayPathChecker {
    fn call(data: &mut Self, _cpu: &mut Cpu, current_addr: u64) {
        if !data.enabled {
            return;
        }

        let last_addr = data.last_block;
        data.last_block = current_addr;

        if let Some(reason) = data.check_jump_legality(last_addr, current_addr) {
            data.suspicious_jumps.push(SuspiciousJump {
                last_addr,
                current_addr,
                reason,
            });
        }
    }
}
