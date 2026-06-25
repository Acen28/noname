
use hashbrown::{HashMap, HashSet};
use std::collections::HashMap as StdHashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeAttribute {
    TypeDirectStatic,
    TypeIndirectStatic,
    TypeDynamicLearned,
}

#[allow(dead_code)]
pub type CfgEdge = (u64, u64, EdgeAttribute);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BasicBlockMetadata {
    pub end_pc: u64,
    pub has_explicit_branch: bool,
}

pub type CfgData = HashMap<u64, Vec<(u64, EdgeAttribute)>>;

pub type CfgBlockMetadata = HashMap<u64, BasicBlockMetadata>;

pub type IsrWhitelist = HashSet<u64>;

pub fn extract_cfg_from_binary(
    elf_path: &Path,
    output_path: &Path,
    ghidra_path: Option<&Path>,
) -> Result<CfgData> {
    let ghidra_install = if let Some(path) = ghidra_path {
        path.to_path_buf()
    } else if let Some(env_path) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        PathBuf::from(env_path)
    } else {
        let mut candidates = Vec::new();

        if let Ok(home) = std::env::var("HOME") {
            candidates.push(PathBuf::from(home).join("ghidra"));
        }

        candidates.push(PathBuf::from("/opt/ghidra"));
        candidates.push(PathBuf::from("/usr/local/ghidra"));

        candidates.push(PathBuf::from("./ghidra"));

        candidates
            .into_iter()
            .find(|p| p.exists() && p.join("support").join("analyzeHeadless").exists())
            .ok_or_else(|| {
                anyhow::format_err!(
                    "Ghidra installation not found. Set GHIDRA_INSTALL_DIR or install Ghidra."
                )
            })?
    };

    let analyze_headless = ghidra_install.join("support").join("analyzeHeadless");

    if !analyze_headless.exists() {
        anyhow::bail!(
            "analyzeHeadless not found at expected path: {}. \
            Note: Do not point to the Ghidra source code repository (icicle submodule). \
            Please point to a release build of Ghidra.",
            analyze_headless.display()
        );
    }

    extract_cfg_with_ghidra(elf_path, output_path, &analyze_headless)
}

fn extract_cfg_with_ghidra(
    elf_path: &Path,
    output_path: &Path,
    analyze_headless: &Path,
) -> Result<CfgData> {
    let script_dir = if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("scripts")
    } else {
        PathBuf::from("scripts")
    };

    let ghidra_script = script_dir.join("extract_cfg_ghidra_script.py");

    if !ghidra_script.exists() {
        anyhow::bail!(
            "Ghidra script not found: {}. Please ensure scripts/extract_cfg_ghidra_script.py exists.",
            ghidra_script.display()
        );
    }

    let temp_dir = std::env::temp_dir().join(format!("ghidra_cfg_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)
        .with_context(|| format!("Failed to create temp directory: {}", temp_dir.display()))?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    let output_path_abs = if output_path.is_absolute() {
        output_path.to_path_buf()
    } else {
        std::env::current_dir()?
            .join(output_path)
            .canonicalize()
            .unwrap_or_else(|_| {
                std::env::current_dir().unwrap().join(output_path)
            })
    };

    let output_path_str = output_path_abs.to_string_lossy().to_string();
    std::env::set_var("CFG_OUTPUT_PATH", &output_path_str);

    eprintln!("[CFG] Extracting CFG from {}...", elf_path.display());

    let output = Command::new(analyze_headless)
        .arg(&temp_dir)
        .arg("CFGProject")
        .arg("-import")
        .arg(elf_path)
        .arg("-processor")
        .arg("ARM:LE:32:Cortex")
        .arg("-scriptPath")
        .arg(script_dir)
        .arg("-postScript")
        .arg("extract_cfg_ghidra_script.py")
        .arg("-deleteProject")
        .output()
        .with_context(|| {
            format!("Failed to execute analyzeHeadless. Make sure Ghidra is properly installed.")
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let _ = std::fs::remove_dir_all(&temp_dir);

    if !output.status.success() {
        let error_summary = if stderr.contains("Error") || stderr.contains("ERROR") {
            let errors: Vec<String> = stderr
                .lines()
                .filter(|l| l.contains("Error") || l.contains("ERROR"))
                .take(10)
                .map(|s| s.to_string())
                .collect();
            if errors.is_empty() {
                stdout
                    .lines()
                    .filter(|l| l.contains("Error") || l.contains("ERROR"))
                    .take(10)
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                errors.join("\n")
            }
        } else {
            format!("Exit code: {}", output.status.code().unwrap_or(-1))
        };

        eprintln!("[CFG] Ghidra stderr output:\n{}", stderr);
        eprintln!(
            "[CFG] Ghidra stdout output (last 50 lines):\n{}",
            stdout
                .lines()
                .rev()
                .take(50)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );

        anyhow::bail!(
            "Ghidra CFG extraction failed: {}\n\nTip: Check if the firmware file is a valid ELF/BIN file and if Ghidra can analyze it.",
            error_summary
        );
    }

    if !output_path.exists() {
        let has_error = stdout.contains("ERROR") || stderr.contains("ERROR");
        let error_msg = if has_error {
            "Script reported errors"
        } else {
            "Script may not have executed"
        };

        eprintln!("[CFG] Script stdout (last 30 lines):");
        let stdout_lines: Vec<&str> = stdout.lines().collect();
        for line in stdout_lines.iter().rev().take(30).rev() {
            eprintln!("[CFG]   {}", line);
        }

        eprintln!("[CFG] Script stderr:");
        for line in stderr.lines() {
            eprintln!("[CFG]   {}", line);
        }

        anyhow::bail!(
            "CFG file not created: {}. {}",
            output_path.display(),
            error_msg
        );
    }

    let cfg_data = load_cfg_from_file(output_path)?;
    eprintln!("[CFG] ✓ Extracted {} basic blocks", cfg_data.len());

    Ok(cfg_data)
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct CfgJsonDataNew {
    cfg: StdHashMap<String, Vec<Vec<String>>>,
}

pub fn load_cfg_from_file(cfg_path: &Path) -> Result<CfgData> {
    let (cfg_data, _) = load_cfg_with_metadata_from_file(cfg_path)?;
    Ok(cfg_data)
}

pub fn load_cfg_with_metadata_from_file(cfg_path: &Path) -> Result<(CfgData, CfgBlockMetadata)> {
    let content = std::fs::read_to_string(cfg_path)
        .with_context(|| format!("Failed to read CFG file: {}", cfg_path.display()))?;

    let json_data: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse CFG JSON: {}", cfg_path.display()))?;

    let cfg_obj = json_data
        .get("cfg")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::format_err!("CFG JSON missing 'cfg' object"))?;

    let mut cfg_u64 = HashMap::new();
    for (addr_str, preds_value) in cfg_obj {
        let addr = parse_hex_address(addr_str)?;
        let mut pred_edges = Vec::new();

        let preds_array = preds_value.as_array().ok_or_else(|| {
            anyhow::format_err!("Invalid predecessor format for block {}", addr_str)
        })?;

        for pred_item in preds_array {
            let pred_array = pred_item
                .as_array()
                .ok_or_else(|| anyhow::format_err!("Invalid predecessor entry format"))?;

            if pred_array.len() < 2 {
                anyhow::bail!(
                    "Invalid predecessor format: expected [addr, attribute], got {:?}",
                    pred_array
                );
            }

            let pred_str = pred_array[0]
                .as_str()
                .ok_or_else(|| anyhow::format_err!("Invalid predecessor address format"))?;
            let attr_str = pred_array[1]
                .as_str()
                .ok_or_else(|| anyhow::format_err!("Invalid attribute format"))?;

            let pred_addr = parse_hex_address(pred_str)?;
            let attr = match attr_str {
                "TYPE_DIRECT_STATIC" => EdgeAttribute::TypeDirectStatic,
                "TYPE_INDIRECT_STATIC" => EdgeAttribute::TypeIndirectStatic,
                "TYPE_DYNAMIC_LEARNED" => EdgeAttribute::TypeDynamicLearned,
                _ => anyhow::bail!("Unknown edge attribute: {}", attr_str),
            };
            pred_edges.push((pred_addr, attr));
        }
        cfg_u64.insert(addr, pred_edges);
    }

    let mut block_metadata = HashMap::new();
    if let Some(metadata_obj) = json_data.get("block_metadata").and_then(|v| v.as_object()) {
        for (addr_str, metadata_value) in metadata_obj {
            let addr = parse_hex_address(addr_str)?;

            if let Some(meta_obj) = metadata_value.as_object() {
                let end_pc = meta_obj
                    .get("end_pc")
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            parse_hex_address(s).ok()
                        } else if let Some(n) = v.as_u64() {
                            Some(n)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        anyhow::format_err!("Invalid end_pc in metadata for block {}", addr_str)
                    })?;

                let has_explicit_branch = meta_obj
                    .get("has_explicit_branch")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                block_metadata.insert(
                    addr,
                    BasicBlockMetadata {
                        end_pc,
                        has_explicit_branch,
                    },
                );
            }
        }
    }

    Ok((cfg_u64, block_metadata))
}

fn parse_hex_address(addr_str: &str) -> Result<u64> {
    let addr_str = addr_str.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(addr_str, 16)
        .with_context(|| format!("Failed to parse hex address: {}", addr_str))
}

pub fn get_cfg_path(firmware_config_path: &Path) -> PathBuf {
    firmware_config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("cfg.json")
}

pub fn ensure_cfg_exists(
    firmware_config: &icicle_cortexm::config::FirmwareConfig,
    force_regenerate: bool,
) -> Result<PathBuf> {
    let config_dir = firmware_config.path.parent().unwrap_or(Path::new("."));

    let mut elf_files: Vec<PathBuf> = Vec::new();
    let mut bin_files: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(config_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    match ext {
                        "elf" => elf_files.push(path),
                        "bin" => bin_files.push(path),
                        _ => {}
                    }
                }
            }
        }
    }

    elf_files.sort();
    bin_files.sort();

    let elf_path: PathBuf = if !elf_files.is_empty() {
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
            matched.clone()
        } else if elf_files.len() == 1 {
            elf_files[0].clone()
        } else {
            elf_files[0].clone()
        }
    } else if !bin_files.is_empty() {
        eprintln!(
            "[CFG] ⚠ Warning: No .elf files found, using .bin file: {}",
            bin_files[0].display()
        );
        eprintln!("[CFG] ⚠ Note: .bin files may not have symbol information. Prefer .elf files for better CFG extraction.");
        bin_files[0].clone()
    } else {
        let dir_name = config_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let mut candidates: Vec<String> = vec![
            "firmware.elf".to_string(),
            "firmware.bin".to_string(),
            "main.elf".to_string(),
        ];

        if !dir_name.is_empty() {
            candidates.push(format!("{}.elf", dir_name));
            candidates.push(format!("{}.bin", dir_name));
        }

        candidates
            .iter()
            .find_map(|name| {
                let path = config_dir.join(name);
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                anyhow::format_err!(
                    "Could not find ELF file in {}. Please specify ELF path or ensure an ELF file exists.",
                    config_dir.display()
                )
            })?
    };

    let cfg_path = get_cfg_path(&firmware_config.path);

    if cfg_path.exists() && !force_regenerate {
        eprintln!(
            "[CFG Extraction] CFG file already exists: {}",
            cfg_path.display()
        );
        return Ok(cfg_path);
    }

    extract_cfg_from_binary(elf_path.as_path(), &cfg_path, None)?;

    Ok(cfg_path)
}

pub fn get_isr_path(firmware_config_path: &Path) -> PathBuf {
    firmware_config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("isr_whitelist.json")
}

pub fn load_isr_from_file(isr_path: &Path) -> Result<IsrWhitelist> {
    let content = std::fs::read_to_string(isr_path)
        .with_context(|| format!("Failed to read ISR file: {}", isr_path.display()))?;

    let json: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse ISR JSON: {}", isr_path.display()))?;

    let mut isr_set = HashSet::new();
    if let Some(valid_isr_array) = json.get("valid_isr_set").and_then(|v| v.as_array()) {
        for addr_str in valid_isr_array {
            if let Some(addr_str) = addr_str.as_str() {
                let addr = u64::from_str_radix(
                    addr_str.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .with_context(|| format!("Failed to parse ISR address: {}", addr_str))?;
                isr_set.insert(addr);
            }
        }
    }

    Ok(isr_set)
}

pub fn save_isr_to_file(
    isr_path: &Path,
    isr_whitelist: &IsrWhitelist,
    false_positives: &HashSet<u64>,
) -> Result<()> {
    let cleaned_isrs: Vec<u64> = isr_whitelist
        .iter()
        .filter(|&addr| !false_positives.contains(addr))
        .copied()
        .collect();

    let mut sorted_isrs = cleaned_isrs;
    sorted_isrs.sort();

    let json = serde_json::json!({
        "valid_isr_set": sorted_isrs.iter().map(|addr| format!("0x{:x}", addr)).collect::<Vec<_>>()
    });

    let content = serde_json::to_string_pretty(&json)
        .with_context(|| "Failed to serialize ISR whitelist to JSON")?;

    std::fs::write(isr_path, content)
        .with_context(|| format!("Failed to write ISR file: {}", isr_path.display()))?;

    Ok(())
}

pub fn ensure_isr_exists(
    firmware_config: &icicle_cortexm::config::FirmwareConfig,
    force_regenerate: bool,
) -> Result<PathBuf> {
    let isr_path = get_isr_path(&firmware_config.path);

    if isr_path.exists() && !force_regenerate {
        return Ok(isr_path);
    }

    let firmware_dir = firmware_config
        .path
        .parent()
        .ok_or_else(|| anyhow::format_err!("Invalid firmware config path"))?;

    let script_path = std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            let script = cwd.join("scripts").join("isr_read.py");
            if script.exists() {
                Some(script)
            } else {
                cwd.parent().map(|p| p.join("scripts").join("isr_read.py"))
            }
        })
        .ok_or_else(|| anyhow::format_err!("Could not find scripts/isr_read.py"))?;

    if !script_path.exists() {
        anyhow::bail!(
            "ISR extraction script not found: {}. Please ensure scripts/isr_read.py exists.",
            script_path.display()
        );
    }

    eprintln!(
        "[ISR] Extracting ISR entry points from {}...",
        firmware_dir.display()
    );

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg(firmware_dir)
        .output()
        .or_else(|_| {
            std::process::Command::new("python")
                .arg(&script_path)
                .arg(firmware_dir)
                .output()
        })
        .with_context(|| format!("Failed to execute isr_read.py script"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ISR extraction script failed: {}\nStderr: {}",
            output.status,
            stderr
        );
    }

    if !isr_path.exists() {
        anyhow::bail!(
            "ISR whitelist file was not created: {}. Script may have failed silently.",
            isr_path.display()
        );
    }

    eprintln!("[ISR] ✓ ISR whitelist written to: {}", isr_path.display());
    Ok(isr_path)
}

pub fn save_cfg_to_file(cfg_path: &Path, cfg_data: &CfgData) -> Result<()> {
    save_cfg_with_metadata_to_file(cfg_path, cfg_data, None)
}

pub fn save_cfg_with_metadata_to_file(
    cfg_path: &Path,
    cfg_data: &CfgData,
    block_metadata: Option<&CfgBlockMetadata>,
) -> Result<()> {
    use std::io::Write;

    let mut json_cfg: StdHashMap<String, Vec<Vec<String>>> = StdHashMap::new();
    for (&addr, pred_edges) in cfg_data {
        let addr_str = format!("0x{:x}", addr);
        let pred_arrays: Vec<Vec<String>> = pred_edges
            .iter()
            .map(|&(pred_addr, attr)| {
                let pred_str = format!("0x{:x}", pred_addr);
                let attr_str = match attr {
                    EdgeAttribute::TypeDirectStatic => "TYPE_DIRECT_STATIC",
                    EdgeAttribute::TypeIndirectStatic => "TYPE_INDIRECT_STATIC",
                    EdgeAttribute::TypeDynamicLearned => "TYPE_DYNAMIC_LEARNED",
                };
                vec![pred_str, attr_str.to_string()]
            })
            .collect();
        json_cfg.insert(addr_str, pred_arrays);
    }

    let mut json_metadata: StdHashMap<String, serde_json::Value> = StdHashMap::new();
    if let Some(metadata) = block_metadata {
        for (&addr, meta) in metadata {
            let addr_str = format!("0x{:x}", addr);
            json_metadata.insert(
                addr_str,
                serde_json::json!({
                    "end_pc": meta.end_pc,
                    "has_explicit_branch": meta.has_explicit_branch,
                }),
            );
        }
    }

    let mut output_data = serde_json::json!({
        "cfg": json_cfg
    });

    if !json_metadata.is_empty() {
        let mut map = serde_json::Map::new();
        for (k, v) in json_metadata {
            map.insert(k, v);
        }
        output_data["block_metadata"] = serde_json::Value::Object(map);
    }

    let temp_path = cfg_path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&temp_path)
            .with_context(|| format!("Failed to create temp CFG file: {}", temp_path.display()))?;
        serde_json::to_writer_pretty(&mut file, &output_data)
            .with_context(|| format!("Failed to write CFG JSON: {}", temp_path.display()))?;
        file.flush()?;
    }

    std::fs::rename(&temp_path, cfg_path)
        .with_context(|| format!("Failed to rename temp CFG file to: {}", cfg_path.display()))?;

    Ok(())
}
