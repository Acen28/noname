# README

## Installation

### 1. Clone

After cloning the repository, initialize the **Ghidra specs submodule** used by the icicle emulator (environment variable `GHIDRA_SRC`, default `./ghidra`):

```bash
git submodule update --init ghidra
```

### 2. Full Ghidra install (headless; for Static CFG extraction)

The first time you fuzz a firmware, if `cfg.json` is not present yet, static CFG is extracted from the ELF via **Ghidra Headless** (`support/analyzeHeadless`). This requires a **full Ghidra release** (not the `ghidra` submodule source tree above).

- Download and unpack from the [Ghidra website](https://ghidra-sre.org/), e.g. `~/ghidra` or `/opt/ghidra`.
- Ensure this exists: `<Ghidra install>/support/analyzeHeadless`.
- If it is not on the default search path, set:
  ```bash
  export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x_PUBLIC
  ```

Point to the **installed** distribution, not the repo’s `ghidra` submodule.

### 3. Rust

Install [Rust](https://rust.rust-lang.org/) (stable), then build from the repository root:

```bash
cargo build --release
```

### 4. Python (Semantic Validator; on by default)

The validator uses Angr; Python 3 is required:

```bash
pip install -r requirements.txt
```

---

## Running

Put the target firmware in its own directory (ELF plus generated `config.yml`, etc.), then from the **repository root**:

```bash
cargo run --release -- ./firmwares/<target>
```

Example:

```bash
WORKDIR=./test RUN_FOR=24h cargo run --release -- ./firmwares/3Dprinter
```

On first run, `config.yml` is generated automatically for ELF targets. Non-ELF targets or missing MCU memory regions may need manual edits. 

> **Note:** We have included all our test firmware samples in the `firmwares/` directory for your convenience. You can directly run them using the command above.
---

## Common environment variables

- `WORKDIR=<path>`: Output directory for the fuzzing session (default `workdir`). Queue, crashes, stats CSVs, validator logs, etc. are written here.

- `RUN_FOR=<time>`: Exit after the given duration, e.g. `RUN_FOR=24h`. Suffixes: `s` (seconds), `m` (minutes), `h` (hours).

- `REPLAY=<path>`: Instead of running the fuzzer, execute the input specified at `<path>`.

- `GDB_BIND=<socket>`: Use with `REPLAY`; bind a gdb-stub and wait for GDB before executing (e.g. `GDB_BIND=127.0.0.1:9001`).

- `GHIDRA_INSTALL_DIR=<path>`: Path to the full Ghidra install (for `analyzeHeadless` CFG extraction).
