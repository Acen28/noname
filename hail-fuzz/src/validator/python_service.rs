//! Python Angr service (persistent process via Socket/Pipe)
//!
//! To avoid the overhead of spawning Python process for each validation,
//! we use a persistent Python service that communicates via Socket or Pipe.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
pub struct ValidationRequest {
    pub dump_dir: String,
    pub target_pc: u64,
    pub last_addr: u64, 
}

#[derive(Serialize, Deserialize)]
pub struct ValidationResponse {
    pub result_type: String, 
    pub targets: Vec<u64>,
    #[serde(default)]
    pub error: Option<String>, 
    #[serde(default)]
    pub debug_info: Option<String>, 
}

pub struct PythonService {
    child: Mutex<Child>,
    #[allow(dead_code)]
    script_path: PathBuf,
}

impl PythonService {
    pub fn start(workdir: &PathBuf) -> anyhow::Result<Self> {
        let script_path = find_validator_script()?;

        eprintln!(
            "[Validator] Starting Python Angr service: {}",
            script_path.display()
        );
        eprintln!(
            "[Validator] Python command: python3 {}",
            script_path.display()
        );

        let log_file_path = workdir.join("validator_angr.log");

        eprintln!(
            "[Validator] Python service logs will be saved to: {}",
            log_file_path.display()
        );

        eprintln!("[Validator] Spawning Python process...");
        let mut child = Command::new("python3")
            .arg(&script_path)
            .env(
                "VALIDATOR_LOG_FILE",
                log_file_path.to_string_lossy().to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!("Failed to start Python service: {}", script_path.display())
            })?;

        eprintln!("[Validator] Python process spawned (PID: {:?})", child.id());

        std::thread::sleep(Duration::from_millis(500));
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = child.stderr.take();
            let mut error_output = String::new();
            if let Some(ref mut stderr_handle) = stderr {
                use std::io::Read;
                let _ = stderr_handle.read_to_string(&mut error_output);
            }

            if !error_output.is_empty() {
                eprintln!(
                    "[Validator] Python service stderr output:\n{}",
                    error_output
                );
                anyhow::bail!(
                    "Python service exited immediately with status: {:?}\nError output:\n{}",
                    status,
                    error_output
                );
            } else {
                anyhow::bail!(
                    "Python service exited immediately with status: {:?} (no error output)",
                    status
                );
            }
        }

        eprintln!("[Validator] Taking stderr handle from child process...");
        let mut stderr = child.stderr.take().unwrap();
        let mut line = String::new();

        use std::io::{BufRead, BufReader};
        let mut stderr_reader = BufReader::new(&mut stderr);
        let start = Instant::now();
        let mut ready = false;
        let timeout = Duration::from_secs(300);

        eprintln!(
            "[Validator] Waiting for Python service to be ready (timeout: {}s)...",
            timeout.as_secs()
        );
        eprintln!("[Validator] Reading from Python stderr, expecting 'READY' signal...");

        while start.elapsed() < timeout {
            line.clear();
            match stderr_reader.read_line(&mut line) {
                Ok(0) => {
                    if let Ok(status) = child.try_wait() {
                        if let Some(status) = status {
                            anyhow::bail!(
                                "Python service exited before sending READY: {:?}",
                                status
                            );
                        }
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    eprintln!("[Validator] Python stderr: {}", trimmed);
                    if trimmed == "READY" {
                        ready = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    eprintln!("[Validator] Error reading stderr: {}", e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        child.stderr = Some(stderr);

        if !ready {
            if let Ok(Some(status)) = child.try_wait() {
                anyhow::bail!("Python service exited with status: {:?}", status);
            }
            anyhow::bail!(
                "Python service did not send READY signal within {}s timeout",
                timeout.as_secs()
            );
        }

        eprintln!("[Validator] Python Angr service started successfully");

        Ok(Self {
            child: Mutex::new(child),
            script_path,
        })
    }

    pub fn validate(
        &self,
        dump_dir: &PathBuf,
        target_pc: u64,
        last_addr: u64,
    ) -> anyhow::Result<ValidationResponse> {

        let mut child_guard = self.child.lock().unwrap();

        if let Some(status) = child_guard.try_wait()? {
            anyhow::bail!(
                "Python service process has exited with status: {:?}",
                status
            );
        }
        let request = ValidationRequest {
            dump_dir: dump_dir.to_string_lossy().to_string(),
            target_pc,
            last_addr, 
        };

        let stdin = child_guard
            .stdin
            .as_mut()
            .context("Python service stdin is not available")?;

        let request_json =
            serde_json::to_string(&request).context("Failed to serialize validation request")?;

        writeln!(stdin, "{}", request_json).context("Failed to write to Python service stdin")?;
        stdin
            .flush()
            .context("Failed to flush Python service stdin")?;

        let stdout = child_guard
            .stdout
            .as_mut()
            .context("Python service stdout is not available")?;

        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();

        eprintln!("[Validator] Reading response from Python service (this may take a while)...");
        eprintln!("[Validator] Python logs are being saved to workdir/validator_angr.log");

        reader
            .read_line(&mut response_line)
            .context("Failed to read from Python service stdout")?;


        let response: ValidationResponse = serde_json::from_str(response_line.trim())
            .with_context(|| format!("Failed to parse validation response: {}", response_line))?;

        Ok(response)
    }
}

impl Drop for PythonService {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            if let Err(e) = child.kill() {
                eprintln!("[Validator] Failed to kill Python service: {}", e);
            }
        }
    }
}

fn find_validator_script() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("VALIDATOR_SCRIPT") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let scripts_script = PathBuf::from("scripts/validator_angr.py");
    if scripts_script.exists() {
        return Ok(scripts_script);
    }

    let hail_scripts_script = PathBuf::from("hail-fuzz/scripts/validator_angr.py");
    if hail_scripts_script.exists() {
        return Ok(hail_scripts_script);
    }

    let current_dir_script = PathBuf::from("validator_angr.py");
    if current_dir_script.exists() {
        return Ok(current_dir_script);
    }

    if let Ok(workdir) = std::env::var("WORKDIR") {
        let workdir_script = PathBuf::from(&workdir).join("scripts/validator_angr.py");
        if workdir_script.exists() {
            return Ok(workdir_script);
        }
        let workdir_script2 = PathBuf::from(&workdir).join("validator_angr.py");
        if workdir_script2.exists() {
            return Ok(workdir_script2);
        }
    }

    anyhow::bail!("Could not find validator_angr.py script. Set VALIDATOR_SCRIPT environment variable or place script in current directory.");
}
