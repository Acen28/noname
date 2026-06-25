//! VM state dumping for Angr bridge
//!
//! Dumps all mapped memory segments (RW, RX, R) to ensure Angr can correctly restore state

use crate::{validator::TaintTracker, Fuzzer};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct VmStateDump {
    pub registers: HashMap<String, u64>,
    pub memory_segments: Vec<MemorySegment>,
    pub pc: u64,
    pub icount: u64,
    pub thumb_mode: bool,
    pub firmware_path: String,
    pub text_range: Option<(u64, u64)>,
    pub mmio_ranges: Vec<(u64, u64)>,
    pub ram_ranges: Vec<(u64, u64)>,
}

#[derive(Serialize, Deserialize)]
pub struct MemorySegment {
    pub start: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub permissions: String,
}

#[derive(Serialize, Deserialize)]
pub struct TaintInfo {
    pub suspect_bytes: Vec<(u64, usize, usize)>,
    pub mmio_access_log: Vec<(u64, u64, usize, usize)>,
    pub crash_pc: u64,
    pub firmware_path: String,
    pub text_range: Option<(u64, u64)>,
    pub mmio_ranges: Vec<(u64, u64)>,
    pub ram_ranges: Vec<(u64, u64)>,
}

pub fn dump_vm_state_for_angr_with_tracker(
    fuzzer: &mut Fuzzer,
    output_dir: &PathBuf,
    tracker: Option<&TaintTracker>,
) -> anyhow::Result<()> {
    dump_vm_state_for_angr_impl(fuzzer, output_dir, tracker, None, None)
}

#[allow(dead_code)]
pub fn dump_vm_state_for_angr_with_metadata(
    fuzzer: &mut Fuzzer,
    output_dir: &PathBuf,
    tracker: Option<&TaintTracker>,
    _last_addr: Option<u64>,
    _cfg_data: Option<&crate::cfg_extraction::CfgData>,
) -> anyhow::Result<()> {
    dump_vm_state_for_angr_impl(fuzzer, output_dir, tracker, None, None)
}

#[allow(dead_code)]
pub fn dump_vm_state_for_angr(
    fuzzer: &mut Fuzzer,
    output_dir: &PathBuf,
    _taint_input: &crate::validator::taint::TaintTrackingMultiStream,
) -> anyhow::Result<()> {
    dump_vm_state_for_angr_impl(fuzzer, output_dir, None, None, None)
}

fn dump_vm_state_for_angr_impl(
    fuzzer: &mut Fuzzer,
    output_dir: &PathBuf,
    tracker: Option<&TaintTracker>,
    _last_addr: Option<u64>,
    _cfg_data: Option<&crate::cfg_extraction::CfgData>,
) -> anyhow::Result<()> {
    let cpu = &mut fuzzer.vm.cpu;

    let mut registers = HashMap::new();

    for i in 0..13 {
        let reg_name = format!("r{}", i);
        let reg_var = cpu
            .arch
            .sleigh
            .get_reg(&reg_name)
            .with_context(|| format!("Failed to get register {}", reg_name))?;
        let value = cpu.read_reg(reg_var.var);
        registers.insert(reg_name, value);
    }

    let sp_var = cpu
        .arch
        .sleigh
        .get_reg("sp")
        .with_context(|| "Failed to get SP register")?;
    registers.insert("sp".to_string(), cpu.read_reg(sp_var.var));

    let lr_var = cpu
        .arch
        .sleigh
        .get_reg("lr")
        .with_context(|| "Failed to get LR register")?;
    registers.insert("lr".to_string(), cpu.read_reg(lr_var.var));

    let current_pc = cpu.read_pc();
    let pc_var = cpu
        .arch
        .sleigh
        .get_reg("pc")
        .with_context(|| "Failed to get PC register")?;
    let pc_reg_value = cpu.read_reg(pc_var.var);
    if pc_reg_value != current_pc && (pc_reg_value & !1) != (current_pc & !1) {
        eprintln!(
            "[Validator] ⚠️ PC register mismatch: read_reg() = 0x{:x}, read_pc() = 0x{:x}",
            pc_reg_value, current_pc
        );
        eprintln!("[Validator] Using read_pc() value for consistency");
    }
    registers.insert("pc".to_string(), current_pc); 

    let xpsr_var = cpu
        .arch
        .sleigh
        .get_reg("xpsr")
        .with_context(|| "Failed to get xPSR register")?;
    registers.insert("xpsr".to_string(), cpu.read_reg(xpsr_var.var));

    let mut memory_segments = Vec::new();

    if let Some(ref firmware_config) = fuzzer.firmware_config {
        for (_name, region) in &firmware_config.memory_map {
            if _name.starts_with("mmio") || _name == "nvic" {
                continue;
            }

            let perms_str = region.permissions.to_str();
            if !perms_str.contains('r') && !perms_str.contains('R') {
                continue;
            }

            let mut data = vec![0u8; region.size as usize];
            match cpu
                .mem
                .read_bytes(region.base_addr, &mut data, icicle_vm::cpu::mem::perm::NONE)
            {
                Ok(_) => {}
                Err(_) => {
                }
            };

            let perms = perms_str.to_string();

            memory_segments.push(MemorySegment {
                start: region.base_addr,
                size: region.size,
                data,
                permissions: perms,
            });
        }
    }

    let xpsr_var = cpu
        .arch
        .sleigh
        .get_reg("xpsr")
        .with_context(|| "Failed to get xPSR register")?;
    let xpsr = cpu.read_reg(xpsr_var.var);
    let thumb_mode = (xpsr & 0x20) != 0;

    let (firmware_path, text_range, mmio_ranges, ram_ranges) =
        if let Some(ref firmware_config) = fuzzer.firmware_config {
            let config_dir = firmware_config
                .path
                .parent()
                .unwrap_or(std::path::Path::new("."));

            let firmware_path = {
                let mut elf_files = Vec::new();
                if let Ok(entries) = std::fs::read_dir(config_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("elf") {
                            elf_files.push(path);
                        }
                    }
                }

                if !elf_files.is_empty() {
                    elf_files.sort();
                    let dir_name = config_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    if let Some(matched) = elf_files.iter().find(|p| {
                        p.file_stem()
                            .and_then(|s| s.to_str())
                            .map_or(false, |stem| {
                                stem == dir_name || stem.contains(&dir_name.replace("_", ""))
                            })
                    }) {
                        matched.to_string_lossy().to_string()
                    } else {
                        elf_files[0].to_string_lossy().to_string()
                    }
                } else {
                    eprintln!(
                        "[Validator] ⚠ Warning: No .elf file found in {}, using config path",
                        config_dir.display()
                    );
                    firmware_config.path.to_string_lossy().to_string()
                }
            };

            let text_range = firmware_config
                .memory_map
                .get("text")
                .map(|text_mem| {
                    let base = text_mem.base_addr;
                    let end = base + text_mem.size;
                    (base, end)
                })
                .or_else(|| {
                    firmware_config
                        .memory_map
                        .values()
                        .find(|mem| {
                            mem.is_entry && {
                                let perm_str = mem.permissions.to_str();
                                perm_str.contains('x')
                            }
                        })
                        .or_else(|| {
                            firmware_config.memory_map.values().find(|mem| {
                                let perm_str = mem.permissions.to_str();
                                perm_str.contains('x')
                            })
                        })
                        .map(|entry_mem| {
                            let base = entry_mem.base_addr;
                            let end = base + entry_mem.size;
                            (base, end)
                        })
                });
            let mmio_ranges: Vec<(u64, u64)> = firmware_config
                .memory_map
                .iter()
                .filter(|(name, _)| {
                    name.starts_with("mmio") || name.as_str() == "nvic"
                })
                .map(|(_, mmio_mem)| {
                    let base = mmio_mem.base_addr;
                    let end = base + mmio_mem.size;
                    (base, end)
                })
                .collect();

            let ram_ranges: Vec<(u64, u64)> = firmware_config
                .memory_map
                .iter()
                .filter(|(name, mem)| {
                    let name_lower = name.to_lowercase();
                    let perm_str = mem.permissions.to_str();
                    name_lower.contains("ram") || 
                (perm_str.contains('w') && !perm_str.contains('x')) ||
                name_lower == "data" || name_lower == "bss"
                })
                .map(|(_, ram_mem)| {
                    let base = ram_mem.base_addr;
                    let end = base + ram_mem.size;
                    (base, end)
                })
                .collect();

            (firmware_path, text_range, mmio_ranges, ram_ranges)
        } else {
            let path = std::env::var("TARGET_CONFIG").unwrap_or_else(|_| "config.yml".to_string());
            (path, None, Vec::new(), Vec::new())
        };

    let mmio_ranges_for_taint = mmio_ranges.clone();
    let ram_ranges_for_taint = ram_ranges.clone();

    let dump = VmStateDump {
        registers,
        memory_segments,
        pc: current_pc,
        icount: cpu.icount(),
        thumb_mode,
        firmware_path: firmware_path.clone(),
        text_range,
        mmio_ranges,
        ram_ranges,
    };

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create directory: {}", output_dir.display()))?;

    std::fs::write(
        output_dir.join("vm_state.json"),
        serde_json::to_string_pretty(&dump).context("Failed to serialize VM state")?,
    )?;

    if let Some(tracker) = tracker {
        let suspect_bytes = tracker.get_all_read_bytes();
        let mmio_access_log = tracker.get_mmio_access_log();

        let taint_info = TaintInfo {
            suspect_bytes,
            mmio_access_log,
            crash_pc: fuzzer.state.exit_address,
            firmware_path: firmware_path.clone(),
            text_range,
            mmio_ranges: mmio_ranges_for_taint, 
            ram_ranges: ram_ranges_for_taint,   
        };

        std::fs::write(
            output_dir.join("taint_info.json"),
            serde_json::to_string_pretty(&taint_info).context("Failed to serialize taint info")?,
        )?;
    }

    Ok(())
}
