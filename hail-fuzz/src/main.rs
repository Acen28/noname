mod cfg_extraction;
mod cfi;
mod config;
mod coverage;
mod debug_alloc;
mod debugging;
mod dictionary;
mod extension;
mod havoc;
mod i2s;
mod input;
mod load_resizer;
mod monitor;
mod mutations;
mod p2im_unit_tests;
mod queue;
mod trim;
mod utils;
mod validator;

use std::{
    any::Any,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use hashbrown::{HashMap, HashSet};
use icicle_cortexm::{config::FirmwareConfig, genconfig, CortexmTarget};
use icicle_fuzzing::{
    cmplog2::CmpLog2Ref, parse_u64_with_prefix, utils::BlockCoverageTracker, CoverageMode,
    CrashKind, FuzzConfig, FuzzTarget, Runnable,
};
use icicle_vm::{
    cpu::{utils::UdpWriter, ExceptionCode},
    Vm, VmExit,
};
use rand::{rngs::SmallRng, seq::SliceRandom, Rng, SeedableRng};

use crate::{
    cfg_extraction::{
        ensure_cfg_exists, ensure_isr_exists, load_cfg_from_file, load_cfg_with_metadata_from_file,
        load_isr_from_file, save_cfg_with_metadata_to_file, save_isr_to_file, CfgData,
        EdgeAttribute, IsrWhitelist,
    },
    cfi::{self as cfi_module, CfiHookRef},
    config::{Config, DebugSettings},
    coverage::{count_all_bits, CoverageAny},
    debugging::trace::{self, PathTracerRef},
    dictionary::{Dictionary, DictionaryRef, MultiStreamDict},
    extension::LengthExtData,
    input::{CortexmMultiStream, MultiStream, StreamKey},
    load_resizer::LoadResizeInjector,
    monitor::{CrashLogger, CrashType, Monitor},
    mutations::random_input,
    queue::{CorpusStore, CoverageQueue, GlobalQueue, GlobalRef, InputId, InputQueue, InputSource},
};

fn main() {
    let logger = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_env("ICICLE_LOG")
            .add_directive("cranelift_jit=warn".parse().unwrap())
            .add_directive("cranelift_codegen=warn".parse().unwrap()),
    );

    match std::env::var("ICICLE_LOG_ADDR").ok() {
        Some(addr) => {
            let addr = Arc::new(addr);
            logger
                .with_writer(move || std::io::BufWriter::new(UdpWriter::new(addr.as_ref())))
                .init()
        }
        None => logger.with_writer(std::io::stderr).init(),
    }

    if let Err(e) = run() {
        eprintln!("Error running fuzzer: {e:?}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    if let Some(path) = std::env::var_os("GENCONFIG") {
        return genconfig::generate_and_save(path.as_ref(), false);
    }
    if let Some(path) = std::env::var_os("FORCE_GENCONFIG") {
        return genconfig::generate_and_save(path.as_ref(), true);
    }

    if std::env::var_os("GHIDRA_SRC").is_none() {
        std::env::set_var("GHIDRA_SRC", "./ghidra");
    }

    let mut fuzzer_config = FuzzConfig::load().expect("Invalid config");

    // Icicle implements a shadow stack to catch return address corruption which is enabled by
    // default. However, this results in false positives crashes for firmware that implements
    // task-switching, so we disable it unless requested by the user.
    if std::env::var_os("ICICLE_ENABLE_SHADOW_STACK").is_none() {
        fuzzer_config.enable_shadow_stack = false;
    }

    if std::env::var_os("COVERAGE_MODE").is_none() {
        fuzzer_config.coverage_mode = CoverageMode::Blocks;
    }

    if let Ok(resume_str) = std::env::var("RESUME") {
        fuzzer_config.resume = resume_str == "1" || resume_str.eq_ignore_ascii_case("true");
    }

    let interrupt_flag = config::add_ctrlc_handler();

    if let Some(path) = std::env::var_os("P2IM_UNIT_TESTS") {
        return p2im_unit_tests::run(fuzzer_config, path.as_ref(), interrupt_flag);
    }

    // We allow the fuzzer config to be passed either as an environment variable or from a file.
    let config_arg = std::env::args().nth(1);
    let firmware_config = match config_arg.as_deref() {
        Some("") | None => FirmwareConfig::from_env()?,
        Some(arg) => FirmwareConfig::from_path(arg.as_ref())?,
    };

    let workdir =
        std::path::PathBuf::from(std::env::var_os("WORKDIR").unwrap_or_else(|| "./workdir".into()));
    let config = Config {
        fuzzer: fuzzer_config,
        workdir,
        firmware: firmware_config,
        interrupt_flag,
    };

    if let Ok(path) = std::env::var("REPLAY") {
        return debugging::replay(config, &path);
    }
    if let Ok(path) = std::env::var("ANALYZE_CRASHES") {
        return debugging::analyze_crashes(config, &path);
    }
    if let Some(path) = std::env::var_os("RUN_I2S_STAGE") {
        return debugging::stage::run_stage(config, path.as_ref(), Stage::InputToState);
    }
    match std::env::var("GEN_BLOCK_COVERAGE").as_deref() {
        Ok("0") | Err(_) => {}
        Ok(mode) => {
            let mode = mode.parse().unwrap();
            return debugging::save_block_coverage(config, mode);
        }
    }

    tracing::info!("Starting fuzzer");
    let _workdir_lock = config::init_workdir(&config).with_context(|| {
        format!(
            "Failed to initialize working directory at: {}",
            config.workdir.display()
        )
    })?;

    let global_queue = Arc::new(GlobalQueue::init(config.fuzzer.workers as usize));
    if config.fuzzer.resume {
        std::fs::create_dir_all(&config.workdir.join("imports"))
            .context("failed to create `imports` dir")?;

        for entry in std::fs::read_dir(&config.workdir.join("imports"))
            .context("failed to read `imports` dir")?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let input = match MultiStream::from_path(&path) {
                    Ok(input) => input,
                    Err(err) => {
                        tracing::error!("error importing `{}`: {err:#}", path.display());
                        continue;
                    }
                };
                global_queue.add_new(usize::MAX, input);
            }
        }
    }

    let monitor = Arc::new(std::sync::Mutex::new(Monitor::new()));
    let global = GlobalRef::new(0, global_queue, Some(monitor));

    let run_for = match std::env::var("RUN_FOR") {
        Ok(duration) => Some(
            utils::parse_duration_str(duration.trim())
                .ok_or_else(|| anyhow::format_err!("Invalid duration specified: {duration}"))?,
        ),
        Err(_) => None,
    };

    std::thread::scope(|s| -> anyhow::Result<()> {
        for id in 1..config.fuzzer.workers {
            tracing::info!("spawning worker: {id}");

            let config = config.clone();
            let global = global.clone_with_id(id as usize);

            std::thread::Builder::new()
                .name(format!("worker-{id}"))
                .spawn_scoped(s, move || {
                    if let Err(e) =
                        Fuzzer::new(config, global).and_then(|fuzzer| fuzzing_loop(fuzzer, run_for))
                    {
                        tracing::error!("Error starting fuzzer for worker {id}: {e:?}");
                    }
                })
                .context("OS failed to spawn worker thread")?;

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let validated_crashes = Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

        let (validator_manager, validator_result_receiver) =
            if icicle_fuzzing::parse_bool_env("ENABLE_VALIDATOR")?.unwrap_or(true) {
                eprintln!("[Validator] Initializing Validator...");

                let (tx, rx) = std::sync::mpsc::channel();

                let manager = crate::validator::ValidatorManager::new(config.clone(), tx);
                eprintln!("[Validator] ValidatorManager created, calling start()...");
                match manager.start() {
                    Ok(()) => {
                        eprintln!("[Validator] ✓ Validator started successfully");
                    }
                    Err(e) => {
                        eprintln!("[Validator] ✗ Failed to start Validator: {}", e);
                        eprintln!("[Validator] Error details: {:#}", e);
                        return Err(e).context("Failed to start Validator");
                    }
                }


                (Some(Arc::new(manager)), Some(rx))
            } else {
                eprintln!("[Validator] Validator is disabled (ENABLE_VALIDATOR=0)");
                (None, None)
            };

        let mut fuzzer = Fuzzer::new(config, global)?;
        fuzzer.validator_manager = validator_manager.clone();
        fuzzer.validator_result_receiver = validator_result_receiver;
        fuzzer.validated_crashes = validated_crashes;

        if let Some(ref validator_manager) = validator_manager {
            if let Some(ref cfi_hook) = fuzzer.cfi_hook {
                if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
                    let learned_edges_arc = cfi.global_learned_edges.clone();
                    validator_manager.set_learned_edges(learned_edges_arc);
                    eprintln!("[Validator] ✓ Set learned_edges reference in ValidatorManager");
                }
            }
        }

        fuzzing_loop(fuzzer, run_for)?;

        Ok(())
    })?;

    Ok(())
}

fn fuzzing_loop(mut fuzzer: Fuzzer, run_for: Option<Duration>) -> anyhow::Result<()> {
    let start_time = std::time::Instant::now();

    let span = tracing::span!(tracing::Level::INFO, "fuzz", id = fuzzer.global.id);
    let _guard = span.enter();

    const VALIDATOR_POLL_INTERVAL: u64 = 1;

    let mut stats = monitor::LocalStats::default();
    while !fuzzer
        .vm
        .interrupt_flag
        .load(std::sync::atomic::Ordering::Relaxed)
        && run_for.map_or(true, |t| start_time.elapsed() < t)
    {
        if fuzzer.execs % VALIDATOR_POLL_INTERVAL == 0 {
            fuzzer.check_validator_results()?;
        }

        fuzzer.state.reset();
        fuzzer.input_id = fuzzer.queue.next_input(&fuzzer.corpus);

        let mut length_ext_prob = 0.9;

        if let Some(id) = fuzzer.input_id {
            let input = &mut fuzzer.corpus[id];

            let is_import = input.is_import;
            let has_unique_edge = input.has_unique_edge;

            if !input.favored && fuzzer.rng.gen_bool(0.95) {
                continue;
            }

            if let std::collections::hash_map::Entry::Vacant(slot) =
                fuzzer.corpus[id].stage_data.entry(Stage::Trim)
            {
                slot.insert(Box::new(()));
                fuzzer.stage = Stage::Trim;
                if fuzzer.features.smart_trim && !is_import {
                    let stage_start = std::time::Instant::now();
                    trim::TrimStage::run(&mut fuzzer, &mut stats)?;
                    fuzzer
                        .perf_stats
                        .record_stage(Stage::Trim, stage_start.elapsed());

                    if has_unique_edge {
                        fuzzer.global.add_new(fuzzer.state.input.clone());
                    }
                }
            }

            if fuzzer.features.cmplog && !is_import {
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    fuzzer.corpus[id].stage_data.entry(Stage::InputToState)
                {
                    slot.insert(Box::new(()));

                    if fuzzer.features.colorization {
                        tracing::debug!("[{id}] running colorization stage");
                        fuzzer.stage = Stage::Colorization;
                        i2s::ColorizationStage::run(&mut fuzzer, &mut stats)?;
                    }

                    tracing::debug!("[{id}] running I2S stage");
                    fuzzer.stage = Stage::InputToState;
                    let stage_start = std::time::Instant::now();
                    i2s::I2SReplaceStage::run(&mut fuzzer, &mut stats)?;
                    fuzzer
                        .perf_stats
                        .record_stage(Stage::InputToState, stage_start.elapsed());
                };
            }

            // If this is the first time we are performing length extension / havoc then update
            // `last_find` to avoid overcounting caused by executions that occured as part of the
            // i2s and trim stages.
            let input = &mut fuzzer.corpus[id];
            if input.metadata.rounds == 0 {
                input.metadata.last_find = input.metadata.execs;
                input.metadata.max_find_gap = 0;
            }
            input.metadata.rounds += 1;
            length_ext_prob = input.length_extension_prob();
        }

        let stage_exit = if !fuzzer.features.havoc || fuzzer.rng.gen_bool(length_ext_prob) {
            fuzzer.stage = Stage::MultiStreamExtend;
            let stage_start = std::time::Instant::now();
            let result = extension::MultiStreamExtendStage::run(&mut fuzzer, &mut stats)?;
            fuzzer
                .perf_stats
                .record_stage(Stage::MultiStreamExtend, stage_start.elapsed());
            result
        } else {
            fuzzer.stage = Stage::Havoc;
            let stage_start = std::time::Instant::now();
            let result = havoc::HavocStage::run(&mut fuzzer, &mut stats)?;
            fuzzer
                .perf_stats
                .record_stage(Stage::Havoc, stage_start.elapsed());
            result
        };

        match stage_exit {
            StageExit::Skip => {}
            StageExit::Unknown(_) | StageExit::Interrupted => break,
            StageExit::Unsupported => {}
        }

        let new_inputs = fuzzer.corpus.inputs() - fuzzer.re_prioritization_inputs;
        if (fuzzer.re_prioritization_cycle != fuzzer.queue.cycles && new_inputs != 0)
            || new_inputs > 20
        {
            fuzzer.corpus.recompute_input_prioritization();
            fuzzer.re_prioritization_cycle = fuzzer.queue.cycles;
            fuzzer.re_prioritization_inputs = fuzzer.corpus.inputs();
        }

        fuzzer.stage = Stage::Import;
        if matches!(
            SyncStage::run(&mut fuzzer, &mut stats)?,
            StageExit::Interrupted
        ) {
            break;
        }
    }

    if fuzzer.global.is_main_instance() {
        eprintln!("Fuzzing stopped, saving data");
        fuzzer.corpus.maybe_save(&fuzzer.workdir)?;

        let _ = std::fs::write(
            fuzzer.workdir.join("disasm.asm"),
            icicle_vm::debug::dump_disasm(&fuzzer.vm).unwrap(),
        );

        let mut coverage = String::new();
        fuzzer.coverage.serialize(&mut fuzzer.vm, &mut coverage);
        std::fs::write(fuzzer.workdir.join("coverage"), coverage)?;

        if icicle_fuzzing::parse_bool_env("DEBUG_IL")?.unwrap_or(false) {
            std::fs::write("il.pcode", icicle_vm::debug::dump_semantics(&fuzzer.vm)?)?;
        }

        // Save CFG and clean ISR whitelist on exit
        if let Some(ref cfi_hook) = fuzzer.cfi_hook {
            if let (Some(ref cfg_path), Some(ref isr_path), Some(ref initial_cfg)) = (
                fuzzer.cfi_cfg_path.as_ref(),
                fuzzer.cfi_isr_path.as_ref(),
                fuzzer.cfi_initial_cfg.as_ref(),
            ) {
                cfi_hook.post_exec_sync(&mut fuzzer.vm);

                // Get learned edges
                let learned_edges = if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
                    let guard = cfi.global_learned_edges.lock().unwrap();
                    guard.clone()
                } else {
                    HashMap::new()
                };

                // Save CFG
                if !learned_edges.is_empty() {
                    let edges_count: usize = learned_edges.values().map(|v| v.len()).sum();
                    eprintln!(
                        "[CFI Persistence] Saving {} learned edges to CFG on exit...",
                        edges_count
                    );

                    let mut merged_cfg: CfgData = (*initial_cfg).clone();
                    for (child, parents) in learned_edges.iter() {
                        let parent_edges: Vec<(u64, EdgeAttribute)> = parents
                            .iter()
                            .map(|&p| (p, EdgeAttribute::TypeDynamicLearned))
                            .collect();
                        merged_cfg
                            .entry(*child)
                            .or_insert_with(Vec::new)
                            .extend(parent_edges);
                    }

                    if let Err(e) = save_cfg_with_metadata_to_file(
                        cfg_path,
                        &merged_cfg,
                        fuzzer.cfi_initial_block_metadata.as_ref(),
                    ) {
                        eprintln!(
                            "[CFI Persistence] ⚠ Failed to save learned edges on exit: {}",
                            e
                        );
                    } else {
                        eprintln!("[CFI Persistence] ✓ Successfully saved {} learned edges to CFG on exit", edges_count);
                    }
                }

                let fp_isrs = if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
                    let guard = cfi.false_positive_isrs.lock().unwrap();
                    guard.clone()
                } else {
                    HashSet::new()
                };

                if !fp_isrs.is_empty() {
                    if let Some(cfi) = cfi_hook.get_mut(&mut fuzzer.vm) {
                        if let Some(ref isr_whitelist_arc) = cfi.isr_whitelist {
                            eprintln!("[CFI Persistence] Cleaning ISR whitelist on exit: removing {} false positive ISR addresses", fp_isrs.len());
                            let isr_whitelist_snapshot = {
                                let guard = isr_whitelist_arc.lock().unwrap();
                                guard.clone()
                            };
                            if let Err(e) =
                                save_isr_to_file(isr_path, &isr_whitelist_snapshot, &fp_isrs)
                            {
                                eprintln!(
                                    "[CFI Persistence] ⚠ Failed to clean ISR whitelist on exit: {}",
                                    e
                                );
                            } else {
                                eprintln!("[CFI Persistence] ✓ Successfully cleaned ISR whitelist on exit");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "stage")]
pub enum MutationKind {
    Extension {
        stream: u64,
        kind: mutations::Extension,
    },
    Mutation {
        stream: u64,
        kind: mutations::Mutation,
    },
}

impl From<(u64, mutations::Extension)> for MutationKind {
    fn from((stream, kind): (u64, mutations::Extension)) -> Self {
        Self::Extension { stream, kind }
    }
}

impl From<(u64, mutations::Mutation)> for MutationKind {
    fn from((stream, kind): (u64, mutations::Mutation)) -> Self {
        Self::Mutation { stream, kind }
    }
}

#[derive(Default)]
pub struct State {
    /// The ID of the parent input.
    pub parent: Option<InputId>,
    /// The type of mutations performed on the source to generate `input`.
    pub mutation_kinds: Vec<MutationKind>,
    /// The current mutated fuzzing input.
    pub input: MultiStream,
    /// Is this input imported from another fuzzing instance.
    pub is_import: bool,
    /// The most recent VmExit generated by the VM.
    pub exit: VmExit,
    /// The pc at the end of the most recent execution.
    pub exit_address: u64,
    /// Did coverage increase after executing the current test case?
    pub new_coverage: bool,
    /// The time it took to execute the input.
    pub exec_time: Duration,
    /// The icount after the fuzzer finished executing the input.
    pub instructions: u64,
    /// Number of bits set in the coverage bitmap for this input (note: only updated if this input
    /// triggered new coverage).
    pub coverage_bits: u64,
    /// The new coverage bits discovered by the current test case
    pub new_bits: Vec<u32>,
    /// The list of coverage entries hit by this input
    pub hit_coverage: Vec<u32>,
    /// CFG edges learned by this input (for optimistic execution and rollback)
    pub learned_cfg_edges: Vec<(u64, u64)>,
    /// Whether this execution is a potential crash (for optimistic execution)
    pub is_potential_crash: bool,
    /// Whether this execution is effectively a crash (considering CFI and MultiFuzz detection)
    pub effective_is_crashing: bool,
}

impl State {
    pub fn reset(&mut self) {
        self.parent = None;
        self.mutation_kinds.clear();
        self.input.clear();
        self.is_import = false;
        self.exit = VmExit::Running;
        self.exit_address = 0;
        self.new_coverage = false;
        self.exec_time = Duration::ZERO;
        self.instructions = 0;
        self.coverage_bits = 0;
        self.hit_coverage.clear();
        self.learned_cfg_edges.clear();
        self.is_potential_crash = false;
        self.effective_is_crashing = false;
    }

    pub fn was_crash(&self) -> bool {
        CrashKind::from(self.exit).is_crash()
    }
    pub fn was_hang(&self) -> bool {
        CrashKind::from(self.exit).is_hang()
    }
}

/// A snapshot of the target at a particular point in time.
pub(crate) struct Snapshot {
    vm: icicle_vm::Snapshot,
    coverage: Box<dyn Any>,
    tracer: Option<trace::PathTracerSnapshot>,
}

impl Snapshot {
    pub fn capture(fuzzer: &mut Fuzzer) -> Self {
        Self {
            vm: fuzzer.vm.snapshot(),
            coverage: fuzzer.coverage.snapshot_local(&mut fuzzer.vm),
            tracer: fuzzer.path_tracer.map(|x| x.snapshot(&mut fuzzer.vm)),
        }
    }

    #[allow(unused)]
    pub fn restore(&self, fuzzer: &mut Fuzzer) {
        fuzzer
            .coverage
            .restore_local(&mut fuzzer.vm, &self.coverage);
        fuzzer.vm.restore(&self.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, self.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }

    pub fn restore_initial(fuzzer: &mut Fuzzer) {
        fuzzer
            .coverage
            .restore_local(&mut fuzzer.vm, &fuzzer.snapshot.coverage);
        fuzzer.vm.restore(&fuzzer.snapshot.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, fuzzer.snapshot.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }

    pub fn restore_prefix(fuzzer: &mut Fuzzer) {
        let snapshot = fuzzer.prefix_snapshot.as_ref().unwrap();
        fuzzer
            .coverage
            .restore_local(&mut fuzzer.vm, &snapshot.coverage);
        fuzzer.vm.restore(&snapshot.vm);
        if let Some(x) = fuzzer.path_tracer {
            x.restore(&mut fuzzer.vm, snapshot.tracer.as_ref().unwrap());
        }
        fuzzer.vm.cpu.mem.mapping_changed = false;
    }
}

pub fn setup_vm(
    config: &mut Config,
    features: &config::EnabledFeatures,
) -> anyhow::Result<(CortexmMultiStream, Vm)> {
    config.firmware.use_access_contexts = features.access_contexts;

    let mut target = CortexmTarget::new();
    let mut vm = target.create_vm(&mut config.fuzzer)?;
    vm.interrupt_flag = config.interrupt_flag.clone();
    vm.icount_limit = config.fuzzer.icount_limit;

    target.fuzzware_init(&config.firmware, &mut vm, MultiStream::default())?;

    if features.resize_load_level > 0 {
        tracing::info!(
            "Registering load_resizer level={}",
            features.resize_load_level
        );
        let multiblock = features.resize_load_level > 1;
        let optimize_upper_bits = features.resize_load_level > 2;
        let mmio = target.mmio_handler.unwrap();
        let mut resizer = LoadResizeInjector::new(mmio, multiblock, optimize_upper_bits);
        for var in &vm.cpu.arch.temporaries {
            resizer.mark_as_temporary(*var);
        }
        vm.add_injector(resizer);
    }

    debugging::enable_checks(&mut vm)?;

    Ok((target, vm))
}

pub(crate) struct Fuzzer {
    /// Directory to store data into.
    pub workdir: PathBuf,
    /// The Vm instance use for executing the target.
    pub vm: Vm,
    /// Controls how to fuzz the target.
    pub target: CortexmMultiStream,
    /// Random number source for the fuzzer..
    pub rng: SmallRng,
    /// The root-level snapshot to restore from when running a new test case.
    pub snapshot: Snapshot,
    /// A snapshot corresponding to the execution from a prefix.
    pub prefix_snapshot: Option<Snapshot>,
    /// The current fuzzing stage.
    pub stage: Stage,
    /// A storage location for test cases.
    pub corpus: CorpusStore<MultiStream>,
    /// A queue for ordering the next test case to fuzz.
    pub queue: CoverageQueue,
    /// The ID of the current input input selected by the fuzzer.
    pub input_id: Option<InputId>,
    /// The state used for generating and monitoring test cases.
    pub state: State,
    /// Stores coverage information for the fuzzer.
    pub coverage: Box<dyn CoverageAny>,
    /// Keeps track of all the crashes discovered by the fuzzer.
    pub crash_logger: CrashLogger,
    /// Additional fuzzer configuration.
    pub config: FuzzConfig,
    /// A reference to the global state shared across fuzzing instances.
    pub global: GlobalRef,
    /// A reference to (optional) tracing instrumentation used for diagnosing fuzzing bugs.
    pub path_tracer: Option<PathTracerRef>,
    /// A reference to CmpLog instrumentation.
    pub cmplog: Option<CmpLog2Ref>,
    /// The blocks seen by the fuzzer with the number of executions and input ID corresponding to
    /// when the first input reaching that block was found.
    pub seen_blocks: BlockCoverageTracker,
    /// Keeps track of bits (by index) in the coverage bitmap found by crashes before regular
    /// inputs.
    pub crash_coverage_bits: HashSet<u32>,
    /// The total number of executions performed by this fuzzing instance.
    pub execs: u64,
    /// The number of execs were were at the last time we found an interesting input.
    pub last_find: u64,
    /// A per stream dictionary.
    pub dict: MultiStreamDict,
    /// A global dictionary.
    pub global_dict: Dictionary,
    /// The total number of inputs stored in `dict`.
    pub dict_items: usize,
    /// The cycle count that we refreshed input prioritization at.
    pub re_prioritization_cycle: usize,
    /// The number of inputs we had when we last refreshed input prioritization.
    pub re_prioritization_inputs: usize,
    /// Controls which fuzzer features should be enabled or not. (used for benchmarking).
    pub features: config::EnabledFeatures,
    /// Controls which debugging features should be enabled.
    pub debug: config::DebugSettings,
    /// CFI Hook reference for control flow integrity checking.
    pub cfi_hook: Option<CfiHookRef>,
    /// Global execution count for CFI
    #[allow(dead_code)]
    pub cfi_current_execs: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// CFG file path for persistence
    pub cfi_cfg_path: Option<PathBuf>,
    /// ISR whitelist file path for persistence
    pub cfi_isr_path: Option<PathBuf>,
    /// Initial CFG data for merging learned edges
    pub cfi_initial_cfg: Option<CfgData>,
    /// Initial block metadata for preserving in saved CFG
    pub cfi_initial_block_metadata: Option<crate::cfg_extraction::CfgBlockMetadata>,
    /// Firmware config (for Validator to access memory map)
    pub firmware_config: Option<icicle_cortexm::config::FirmwareConfig>,
    /// Validator manager (only on main instance)
    pub validator_manager: Option<Arc<crate::validator::ValidatorManager>>,
    /// Validator result receiver (only on main instance)
    pub validator_result_receiver: Option<
        std::sync::mpsc::Receiver<(
            crate::validator::ValidatorTask,
            crate::validator::ValidationResult,
        )>,
    >,
    pub validated_crashes: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<(u64, u64)>>>,
    pub perf_stats: PerfStats,
    pub abort_current_seed: bool,
}

#[derive(Default)]
pub struct PerfStats {
    pub vm_exec_count: std::sync::atomic::AtomicU64,
    pub vm_exec_total_us: std::sync::atomic::AtomicU64,

    pub trim_total_us: std::sync::atomic::AtomicU64,
    pub trim_count: std::sync::atomic::AtomicU64,
    pub havoc_total_us: std::sync::atomic::AtomicU64,
    pub havoc_count: std::sync::atomic::AtomicU64,
    pub i2s_total_us: std::sync::atomic::AtomicU64,
    pub i2s_count: std::sync::atomic::AtomicU64,
    pub extend_total_us: std::sync::atomic::AtomicU64,
    pub extend_count: std::sync::atomic::AtomicU64,

    pub snapshot_restore_total_us: std::sync::atomic::AtomicU64,
    pub snapshot_restore_count: std::sync::atomic::AtomicU64,
    pub input_write_total_us: std::sync::atomic::AtomicU64,
    pub input_write_count: std::sync::atomic::AtomicU64,
    pub coverage_check_total_us: std::sync::atomic::AtomicU64,
    pub coverage_check_count: std::sync::atomic::AtomicU64,
    pub queue_select_total_us: std::sync::atomic::AtomicU64,
    pub queue_select_count: std::sync::atomic::AtomicU64,
}

impl PerfStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_vm_exec(&self, duration: Duration) {
        self.vm_exec_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.vm_exec_total_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn record_stage(&self, stage: Stage, duration: Duration) {
        let duration_us = duration.as_micros() as u64;
        match stage {
            Stage::Trim => {
                self.trim_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.trim_total_us
                    .fetch_add(duration_us, std::sync::atomic::Ordering::Relaxed);
            }
            Stage::Havoc => {
                self.havoc_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.havoc_total_us
                    .fetch_add(duration_us, std::sync::atomic::Ordering::Relaxed);
            }
            Stage::InputToState => {
                self.i2s_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.i2s_total_us
                    .fetch_add(duration_us, std::sync::atomic::Ordering::Relaxed);
            }
            Stage::MultiStreamExtend | Stage::MultiStreamExtendI2S => {
                self.extend_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.extend_total_us
                    .fetch_add(duration_us, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_snapshot_restore(&self, duration: Duration) {
        self.snapshot_restore_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.snapshot_restore_total_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn record_input_write(&self, duration: Duration) {
        self.input_write_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.input_write_total_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn record_coverage_check(&self, duration: Duration) {
        self.coverage_check_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.coverage_check_total_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn record_queue_select(&self, duration: Duration) {
        self.queue_select_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.queue_select_total_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn snapshot(&self) -> PerfStatsSnapshot {
        use std::sync::atomic::Ordering;
        PerfStatsSnapshot {
            vm_exec_count: self.vm_exec_count.load(Ordering::Relaxed),
            vm_exec_avg_us: {
                let count = self.vm_exec_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.vm_exec_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            trim_avg_us: {
                let count = self.trim_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.trim_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            trim_count: self.trim_count.load(Ordering::Relaxed),
            havoc_avg_us: {
                let count = self.havoc_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.havoc_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            havoc_count: self.havoc_count.load(Ordering::Relaxed),
            i2s_avg_us: {
                let count = self.i2s_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.i2s_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            i2s_count: self.i2s_count.load(Ordering::Relaxed),
            extend_avg_us: {
                let count = self.extend_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.extend_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            extend_count: self.extend_count.load(Ordering::Relaxed),
            snapshot_restore_avg_us: {
                let count = self.snapshot_restore_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.snapshot_restore_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            input_write_avg_us: {
                let count = self.input_write_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.input_write_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            coverage_check_avg_us: {
                let count = self.coverage_check_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.coverage_check_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
            queue_select_avg_us: {
                let count = self.queue_select_count.load(Ordering::Relaxed);
                if count > 0 {
                    self.queue_select_total_us.load(Ordering::Relaxed) / count
                } else {
                    0
                }
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PerfStatsSnapshot {
    pub vm_exec_count: u64,
    pub vm_exec_avg_us: u64,
    pub trim_avg_us: u64,
    pub trim_count: u64,
    pub havoc_avg_us: u64,
    pub havoc_count: u64,
    pub i2s_avg_us: u64,
    pub i2s_count: u64,
    pub extend_avg_us: u64,
    pub extend_count: u64,
    pub snapshot_restore_avg_us: u64,
    pub input_write_avg_us: u64,
    pub coverage_check_avg_us: u64,
    pub queue_select_avg_us: u64,
}

impl Fuzzer {
    pub fn new_debug(config: Config) -> anyhow::Result<Self> {
        let global_queue = Arc::new(GlobalQueue::init(1));
        let monitor = Arc::new(std::sync::Mutex::new(Monitor::new()));
        let global = GlobalRef::new(0, global_queue, Some(monitor));
        Self::new(config, global)
    }

    pub fn new(mut config: Config, global: GlobalRef) -> anyhow::Result<Self> {
        let features = config::EnabledFeatures::from_env()?;
        eprintln!("HailFuzz start with features: {features:?}");
        let (mut target, mut vm) = setup_vm(&mut config, &features)?;
        icicle_fuzzing::add_debug_instrumentation(&mut vm);

        let mut path_tracer = None;
        if config.fuzzer.track_path {
            path_tracer = Some(trace::add_path_tracer(
                &mut vm,
                target.mmio_handler.unwrap(),
            )?);
        }

        let mut cmplog = None;
        if features.cmplog {
            let check_indirect =
                icicle_fuzzing::parse_bool_env("CMPLOG_CHECK_INDIRECT")?.unwrap_or(false);
            let skip_call_instrumentation =
                icicle_fuzzing::parse_bool_env("CMPLOG_NO_CALLS")?.unwrap_or(false);
            cmplog = Some(
                icicle_fuzzing::cmplog2::CmpLog2Builder::new()
                    .instrument_calls(!skip_call_instrumentation)
                    .check_indirect_pointers(check_indirect)
                    .finish(&mut vm),
            );
        }
        // Initialize CFI Hook if enabled
        let mut cfi_hook = None;
        let mut cfi_cfg_path = None;
        let mut cfi_isr_path = None;
        let mut cfi_initial_cfg = None;
        let mut cfi_initial_block_metadata = None; 
        let current_execs = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // Default: enabled (can be disabled by setting ENABLE_CFI=0)
        if icicle_fuzzing::parse_bool_env("ENABLE_CFI")?.unwrap_or(true) {
            eprintln!("[CFI] Initializing CFI enforcement...");

            // Load CFG and ISR whitelist
            let cfg_path = ensure_cfg_exists(&config.firmware, false).ok();
            let (cfg_data, block_metadata): (
                Option<CfgData>,
                Option<crate::cfg_extraction::CfgBlockMetadata>,
            ) = if let Some(cfg_path) = cfg_path.as_ref() {
                match load_cfg_with_metadata_from_file(cfg_path) {
                    Ok((cfg, metadata)) => (Some(cfg), Some(metadata)),
                    Err(_) => {
                        (load_cfg_from_file(cfg_path).ok(), None)
                    }
                }
            } else {
                (None, None)
            };

            let isr_path = ensure_isr_exists(&config.firmware, false).ok();
            let isr_whitelist = isr_path
                .as_ref()
                .and_then(|isr_path| load_isr_from_file(isr_path).ok());

            let text_range = config
                .firmware
                .memory_map
                .get("text")
                .map(|text_mem| {
                    let base = text_mem.base_addr;
                    let end = base + text_mem.size;
                    (base, end)
                })
                .or_else(|| {
                    config
                        .firmware
                        .memory_map
                        .values()
                        .find(|mem| {
                            mem.is_entry && {
                                let perm_str = mem.permissions.to_str();
                                perm_str.contains('x')
                            }
                        })
                        .or_else(|| {
                            config.firmware.memory_map.values().find(|mem| {
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

            if text_range.is_none() {
                eprintln!("[CFI] ⚠ Warning: No 'text' section or executable entry section found in config.yml, CFI text range check will be disabled");
            } else {
                let (base, end) = text_range.unwrap();
                eprintln!("[CFI] Text section range: 0x{:x} - 0x{:x}", base, end);
            }

            // Save paths for persistence
            cfi_cfg_path = cfg_path;
            cfi_isr_path = isr_path;
            cfi_initial_cfg = cfg_data.clone(); 
            cfi_initial_block_metadata = block_metadata.clone(); 
            let hook = cfi_module::add_cfi_hook(&mut vm)?;
            hook.initialize(
                &mut vm,
                cfg_data,
                block_metadata,
                isr_whitelist.clone(),
                text_range,
                current_execs.clone(),
            )?;
            cfi_hook = Some(hook);
            eprintln!("[CFI] ✓ CFI enforcement enabled");

            // Start background persistence thread (only on main instance)
            if let (Some(cfg_path), Some(isr_path)) = (cfi_cfg_path.as_ref(), cfi_isr_path.as_ref())
            {
                if let Some(ref hook_ref) = cfi_hook.as_ref() {
                    // Get references from hook before moving to thread
                    let learned_edges_arc = hook_ref
                        .get_mut(&mut vm)
                        .map(|cfi| cfi.global_learned_edges.clone())
                        .unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));
                    let false_positive_isrs_arc = hook_ref
                        .get_mut(&mut vm)
                        .map(|cfi| cfi.false_positive_isrs.clone())
                        .unwrap_or_else(|| Arc::new(Mutex::new(HashSet::new())));
                    let isr_whitelist_arc = hook_ref.get_isr_whitelist(&mut vm);


                    let cfg_path_clone = cfg_path.clone();
                    let isr_path_clone = isr_path.clone();
                    let current_execs_clone = current_execs.clone();
                    let initial_cfg_clone = cfi_initial_cfg.clone();
                    let initial_block_metadata_clone = cfi_initial_block_metadata.clone(); // 🚨 新增

                    std::thread::spawn(move || {
                        cfi_persistence_thread(
                            cfg_path_clone,
                            isr_path_clone,
                            learned_edges_arc,
                            false_positive_isrs_arc,
                            isr_whitelist_arc,
                            current_execs_clone,
                            initial_cfg_clone,
                            initial_block_metadata_clone, 
                        );
                    });
                    eprintln!("[CFI] ✓ Background persistence thread started");
                }
            }
        }

        let mut coverage = config::configure_coverage(&config.fuzzer, &mut vm);
        target.initialize_vm(&config.fuzzer, &mut vm)?;
        coverage.reset(&mut vm);

        // Execute until the first MMIO address is read.
        let exit = target.run(&mut vm)?;
        if !matches!(
            exit,
            VmExit::UnhandledException((ExceptionCode::ReadWatch, _))
        ) {
            anyhow::bail!(
                "Failed to initialize VM for fuzzing execution, unexpected initial exit: {}\ncallstack:\n{}",
                target.exit_string(exit),
                icicle_vm::debug::backtrace(&mut vm)
            );
        }

        let snapshot = Snapshot {
            vm: vm.snapshot(),
            coverage: coverage.snapshot_local(&mut vm),
            tracer: path_tracer.map(|x| x.snapshot(&mut vm)),
        };
        let state = State {
            input: MultiStream::default(),
            ..State::default()
        };

        let rng = match std::env::var("SEED") {
            Ok(seed) => {
                let seed = parse_u64_with_prefix(&seed)
                    .ok_or_else(|| anyhow::format_err!("expected number for seed: {seed}"))?;
                tracing::info!("Using fixed seed: {seed:#x}");
                SmallRng::seed_from_u64(seed)
            }
            Err(_) => SmallRng::from_entropy(),
        };

        let crash_logger = CrashLogger::new(&config)?;

        let mut global_dict = Dictionary::default();
        if let Some(dict_path) = std::env::var_os("DICTIONARY") {
            let input = std::fs::read_to_string(&dict_path).with_context(|| {
                format!(
                    "failed to read dictionary file: {}",
                    AsRef::<Path>::as_ref(&dict_path).display()
                )
            })?;
            for entry in input.split_whitespace() {
                global_dict.add_item(entry.as_bytes(), 1 | 2 | 4);
            }
            global_dict.compute_weights();
        }

        Ok(Self {
            workdir: config.workdir,
            vm,
            perf_stats: PerfStats::new(),
            target,
            snapshot,
            prefix_snapshot: None,
            queue: CoverageQueue::new(),
            stage: Stage::MultiStreamExtend,
            rng,
            corpus: CorpusStore::default(),
            input_id: None,
            state,
            coverage,
            crash_logger,
            config: config.fuzzer,
            global,
            path_tracer,
            firmware_config: Some(config.firmware),
            cmplog,
            seen_blocks: BlockCoverageTracker::new(),
            crash_coverage_bits: HashSet::new(),
            execs: 0,
            last_find: 0,
            dict: HashMap::new(),
            global_dict,
            dict_items: 0,
            re_prioritization_cycle: 0,
            re_prioritization_inputs: 0,
            features,
            debug: DebugSettings::from_env()?,
            cfi_hook,
            cfi_current_execs: if cfi_hook.is_some() {
                Some(current_execs)
            } else {
                None
            },
            cfi_cfg_path,
            cfi_isr_path,
            cfi_initial_cfg,
            cfi_initial_block_metadata, 
            validator_manager: None,
            validator_result_receiver: None,
            validated_crashes: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            abort_current_seed: false,
        })
    }

    fn crash_dedup_text_range(&mut self) -> Option<(u64, u64)> {
        if let Some(ref hook) = self.cfi_hook {
            if let Some(cfi) = hook.get_mut(&mut self.vm) {
                if let Some(range) = cfi.text_range {
                    return Some(range);
                }
            }
        }
        self.firmware_config.as_ref().and_then(|fc| {
            fc.memory_map
                .get("text")
                .map(|t| (t.base_addr, t.base_addr + t.size))
        })
    }

    fn check_validator_results(&mut self) -> anyhow::Result<()> {
        let cold_start_execs = config::cold_start_execs();
        if cold_start_execs > 0 && self.execs < cold_start_execs {
            return Ok(()); 
        }

        let mut pending_tasks = Vec::new();
        if let Some(ref rx) = self.validator_result_receiver {
            while let Ok((task, result)) = rx.try_recv() {
                pending_tasks.push((task, result));
            }
        }

        for (task, result) in pending_tasks {
            match result {
                crate::validator::ValidationResult::TrueCrash => {
                    eprintln!(
                        "[Fuzzer] 🔥 True Crash confirmed for input {} (0x{:x} -> 0x{:x}), starting rollback cleanup",
                        task.crash_input_id, task.last_addr, task.current_addr
                    );

                    self.save_true_crash(&task)?;

                    if task.crash_input_id != usize::MAX {
                        self.purge_crash_and_rollback_cfg(
                            task.crash_input_id,
                            task.last_addr,
                            task.current_addr,
                        );
                    }else {
                        if let Some(ref cfi_hook) = self.cfi_hook {
                            if let Some(cfi) = cfi_hook.get_mut(&mut self.vm) {
                                cfi.remove_learned_edge(task.last_addr, task.current_addr);
                                eprintln!(
                                    "[Fuzzer] 🧹 Revoked edge 0x{:x} -> 0x{:x} (seed not in corpus)",
                                    task.last_addr, task.current_addr
                                );
                            }
                        }
                    }
                }
                crate::validator::ValidationResult::ValidJump(targets) => {
                    eprintln!(
                        "[Fuzzer] ✓ Valid jump targets for input {}: {:?}",
                        task.crash_input_id, targets
                    );
                    self.handle_valid_jump(&task, &targets)?;
                }
                crate::validator::ValidationResult::Unknown => {
                    eprintln!(
                        "[Fuzzer] ⚠️ Validator returned Unknown for input {} (0x{:x} -> 0x{:x}). Saving to suspicious.",
                        task.crash_input_id, task.last_addr, task.current_addr
                    );
                    self.save_suspicious_input(&task)?;
                }
            }
        }
        Ok(())
    }

    fn save_true_crash(&mut self, task: &crate::validator::ValidatorTask) -> anyhow::Result<()> {
        if task.crash_input_id >= self.corpus.inputs() {
            return Ok(()); 
        }

        let crash_input = &self.corpus[task.crash_input_id].data;

        let fake_exit = VmExit::UnhandledException((
            icicle_vm::cpu::ExceptionCode::Environment,
            task.current_addr,
        ));

        let original_input = self.state.input.clone();
        let original_exit = self.state.exit;
        let original_parent = self.state.parent;
        self.state.input.clone_from(crash_input);
        self.state.exit = fake_exit;
        self.state.parent = self.corpus[task.crash_input_id].metadata.parent_id;

        let text_range = self.crash_dedup_text_range();
        if let Some(key) = self.crash_logger.add_if_new(
            &mut self.vm,
            &self.state,
            text_range,
            Some(CrashType::Validated),
        ) {
            let cfi_crash_info: Option<(u64, u64, Option<crate::cfi::CfiCrashType>)> =
                Some((task.last_addr, task.current_addr, None));

            if let Ok(mut validated) = self.validated_crashes.lock() {
                validated.insert((task.last_addr, task.current_addr));
            }

            if self
                .global
                .add_crash_or_hang(key.clone(), CrashKind::from(fake_exit))
            {
                if let Err(e) = self.crash_logger.save(
                    &self.state,
                    &mut self.vm,
                    &self.target,
                    fake_exit,
                    cfi_crash_info,
                    true,
                    Some(&key),
                ) {
                    eprintln!("[Fuzzer] ⚠️ Failed to save True Crash: {}", e);
                } else {
                    eprintln!("[Fuzzer] ✓ Saved True Crash to crashes directory");
                }
            }
        }

        self.state.input = original_input;
        self.state.exit = original_exit;
        self.state.parent = original_parent;

        Ok(())
    }

    fn purge_crash_and_rollback_cfg(
        &mut self,
        crash_input_id: crate::queue::InputId,
        last_addr: u64,
        current_addr: u64,
    ) {
        let ids_to_disable = self.corpus.collect_seed_and_descendants(crash_input_id);
        let exclusive_coverage_bits = self.corpus.count_exclusive_coverage_bits(&ids_to_disable);
        let disabled_ids = self.corpus.disable_seed_and_descendants(crash_input_id);
        eprintln!("[Fuzzer] Disabled {} seeds", disabled_ids.len());

        {
            use std::io::Write;
            let path = self.workdir.join("rollback_stats.csv");
            let needs_header = !path.exists();
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                if needs_header {
                    let _ = file.write_all(
                        b"time_ms,execs,root_input_id,disabled_count,exclusive_coverage_bits,last_addr,current_addr\n",
                    );
                }
                let time_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let _ = file.write_all(
                    format!(
                        "{},{},{},{},{},0x{:x},0x{:x}\n",
                        time_ms,
                        self.execs,
                        crash_input_id,
                        disabled_ids.len(),
                        exclusive_coverage_bits,
                        last_addr,
                        current_addr,
                    )
                    .as_bytes(),
                );
            }
        }

        if let Some(ref validator_manager) = self.validator_manager {
            validator_manager.mark_seeds_disabled(&disabled_ids);
        }

        if let Some(ref cfi_hook) = self.cfi_hook {
            let mut removed_edges = 0;
            for &disabled_id in &disabled_ids {
                let learned_edges = self.corpus[disabled_id].metadata.learned_cfg_edges.clone();
                for (src, dst) in learned_edges {
                    if let Some(cfi) = cfi_hook.get_mut(&mut self.vm) {
                        cfi.remove_learned_edge(src, dst);
                        removed_edges += 1;
                        eprintln!(
                            "[Fuzzer] 🧹 Removed edge 0x{:x} -> 0x{:x} from CFG model",
                            src, dst
                        );
                    }
                }
            }
            eprintln!(
                "[Fuzzer] 🧹 Rollback cleanup complete: removed {} edges from CFG model",
                removed_edges
            );
        }
    }

    fn handle_valid_jump(
        &mut self,
        task: &crate::validator::ValidatorTask,
        targets: &[u64],
    ) -> anyhow::Result<()> {
        if let Some(ref validator_manager) = self.validator_manager {
            match validator_manager.get_learned_edges().lock() {
                Ok(guard) => {
                    if let Some(ref learned_edges_arc) = *guard {
                        let edges_result: Result<
                            std::sync::MutexGuard<'_, HashMap<u64, Vec<u64>>>,
                            _,
                        > = learned_edges_arc.lock();
                        if let Ok(mut edges) = edges_result {
                            edges
                                .entry(task.current_addr)
                                .or_insert_with(Vec::new)
                                .push(task.last_addr);

                            for target in targets {
                                edges
                                    .entry(*target)
                                    .or_insert_with(Vec::new)
                                    .push(task.last_addr);
                            }

                            eprintln!(
                                "[Fuzzer] ✓ Added valid jump edge(s) to CFG: 0x{:x} -> 0x{:x}",
                                task.last_addr, task.current_addr
                            );
                        }
                    }
                }
                Err(_) => {
                    eprintln!("[Fuzzer] ⚠️ Failed to lock learned_edges, cannot update CFG");
                }
            }
        }
        Ok(())
    }

    fn save_suspicious_input(&self, task: &crate::validator::ValidatorTask) -> anyhow::Result<()> {
        if task.crash_input_id >= self.corpus.inputs() {
            return Ok(()); 
        }

        let suspicious_dir = self.workdir.join("suspicious");
        std::fs::create_dir_all(&suspicious_dir).with_context(|| {
            format!(
                "Failed to create suspicious directory: {}",
                suspicious_dir.display()
            )
        })?;

        let crash_input = &self.corpus[task.crash_input_id].data;
        let filename = format!("0x{:x}_0x{:x}_unknown", task.last_addr, task.current_addr);
        let path = suspicious_dir.join(filename);

        std::fs::write(&path, crash_input.to_bytes())
            .with_context(|| format!("Failed to save suspicious input: {}", path.display()))?;

        eprintln!("[Fuzzer] ✓ Saved suspicious input to {}", path.display());
        Ok(())
    }

    /// Copies the currently selected input into `state`.
    pub fn copy_current_input(&mut self) {
        self.state.reset();
        self.state.parent = self.input_id;
        match self.input_id {
            Some(id) if id < self.corpus.inputs() => {
                self.state.input.clone_from(&self.corpus[id].data)
            }
            _ => random_input(self), 
        };
    }

    /// Runs the VM until it exits and updates the current fuzzing state.
    pub fn execute(&mut self) -> Option<VmExit> {
        self.execute_with_limit(self.config.icount_limit)
    }

    /// Runs the VM until it exits or executs `limit` number of instructions and update the current
    /// fuzzing state.
    pub fn execute_with_limit(&mut self, limit: u64) -> Option<VmExit> {
        let exec_start = std::time::Instant::now();

        // Reset CFI hook execution state for new input
        if let Some(ref cfi_hook) = self.cfi_hook {
            cfi_hook.reset_execution_state(&mut self.vm);
        }

        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = limit;
        if let Some(cmplog) = self.cmplog {
            cmplog.clear_data(&mut self.vm.cpu);
        }
        let exit = self.target.run(&mut self.vm).unwrap();
        self.vm.icount_limit = old_limit;
        self.execs += 1;

        self.state.exec_time = exec_start.elapsed();
        self.state.instructions = self.vm.cpu.icount();
        self.state.exit = exit;
        self.state.exit_address = self.vm.cpu.read_pc();

        self.perf_stats.record_vm_exec(self.state.exec_time);

        if matches!(exit, VmExit::Interrupted) {
            return None;
        }

        if self.global.is_main_instance() {
            let new_blocks = self
                .seen_blocks
                .add_new(&self.vm.code, self.corpus.inputs() as u64);
            if self.features.dump_jit_mapping && new_blocks {
                if let Err(e) = self
                    .vm
                    .jit
                    .dump_jit_mapping("jit_table.txt".as_ref(), self.vm.env.debug_info().unwrap())
                {
                    tracing::warn!("Failed to dump JIT table: {e}")
                }
            }

            if let Err(e) = self
                .seen_blocks
                .maybe_save(&self.workdir.join("cur_coverage.txt"))
            {
                tracing::error!("error saving coverage file: {e:?}");
            }
            let _ = self.corpus.maybe_save(&self.workdir);
        }

        Some(exit)
    }

    pub fn check_exit_state(&mut self, exit: VmExit) -> anyhow::Result<()> {
        if self.state.input.total_bytes() == 0 {
            // Discard zero length inputs, these can sometimes occur as a result of trimming very
            // small inputs.
            self.state.mutation_kinds.clear();
            return Ok(());
        }

        let crash_kind = CrashKind::from(exit);

        // Update CFI execution count and sync learned edges
        if let Some(ref cfi_hook) = self.cfi_hook {
            cfi_hook.update_exec_count(&mut self.vm, self.execs);
            cfi_hook.post_exec_sync(&mut self.vm);
        }

        let (is_potential_crash, potential_crash_list) = if let Some(ref cfi_hook) = self.cfi_hook {
            let cold_start_execs = config::cold_start_execs();
            if cold_start_execs > 0 && self.execs < cold_start_execs {
                (false, Vec::new())
            } else if cfi_hook.has_potential_crash(&mut self.vm) {
                let crashes = cfi_hook.get_potential_crashes(&mut self.vm);
                if !crashes.is_empty() {
                    if let Some(cfi) = cfi_hook.get_mut(&mut self.vm) {
                        cfi.has_potential_crash = false;
                        cfi.potential_crash_info.clear();
                    }
                    (true, crashes)
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

        let cfi_crash_info: Option<(u64, u64, Option<crate::cfi::CfiCrashType>)> =
            if let Some(ref cfi_hook) = self.cfi_hook {
                if let Some((last_addr, current_addr, crash_type)) =
                    cfi_hook.get_true_crash(&mut self.vm)
                {
                    if let Some(cfi) = cfi_hook.get_mut(&mut self.vm) {
                        cfi.true_crash_info = None;
                    }
                    eprintln!(
                        "[CFI] True Crash detected: 0x{:x} -> 0x{:x} (type: {:?})",
                        last_addr, current_addr, crash_type
                    );
                    Some((last_addr, current_addr, Some(crash_type)))
                } else {
                    None
                }
            } else {
                None
            };

        if is_potential_crash {
            self.state.is_potential_crash = true;

            for (last_addr, current_addr) in potential_crash_list {
                let _ = self.crash_logger.add_potential_crash(
                    &mut self.vm,
                    &self.state,
                    last_addr,
                    current_addr,
                );

                if let Some(ref cfi_hook) = self.cfi_hook {
                    if let Some(cfi) = cfi_hook.get_mut(&mut self.vm) {
                        cfi.add_learned_edge(last_addr, current_addr);
                    }
                }

                self.state.learned_cfg_edges.push((last_addr, current_addr));

                if let Some(ref validator) = self.validator_manager {
                    let input_id = self.input_id.unwrap_or(usize::MAX);
                    if input_id == usize::MAX || !self.corpus.is_seed_disabled(input_id) {
                        let task = crate::validator::ValidatorTask {
                            crash_input: self.state.input.clone(),
                            crash_input_id: input_id,
                            last_addr,
                            current_addr,
                            workdir: self.workdir.clone(),
                        };
                        validator.add_task(task);
                    }
                }
            }
        } else {
            self.state.is_potential_crash = false;
        }

        let is_environment_exception = matches!(
            exit,
            VmExit::UnhandledException((icicle_vm::cpu::ExceptionCode::Environment, _))
        );

        if is_environment_exception && cfi_crash_info.is_none() && !is_potential_crash {
            return Ok(());
        }

        self.state.new_bits = self.coverage.new_bits(&mut self.vm);
        self.state.new_coverage = !self.state.new_bits.is_empty();
        if self.state.new_coverage {
            let bits = self.coverage.get_bits(&mut self.vm);
            self.state.coverage_bits = count_all_bits(bits);
            self.state.hit_coverage = coverage::bit_iter(bits).map(|x| x as u32).collect();

            if tracing::enabled!(tracing::Level::TRACE) {
                self.trace_new_bits();
            }
        }

        let effective_crash_kind = if is_potential_crash {
            false 
        } else if cfi_crash_info.is_some() {
            true 
        } else if config::enable_multifuzz_crash_detection() {
            crash_kind.is_crash()
        } else {
            false
        };

        self.state.effective_is_crashing = effective_crash_kind;

        if !effective_crash_kind {
            if self.state.new_coverage {
                if config::VALIDATE {
                    debugging::validate_last_exec(self, exit);
                }
                self.coverage.merge(&mut self.vm);
                self.state
                    .hit_coverage
                    .iter()
                    .for_each(|bit| _ = self.crash_coverage_bits.remove(bit));
                tracing::debug!("{} bits set in coverage map", self.coverage.count());
            } else if self.features.add_favored_inputs
                && self.queue.new_inputs() == 0
                && self.stage != Stage::Trim
                && self.rng.gen_bool(0.01)
            {
                // Occasionally check if the current input is favored over previous entries.
                let bits = self.coverage.get_bits(&mut self.vm);
                self.state.coverage_bits = count_all_bits(bits);
                self.state.hit_coverage = coverage::bit_iter(bits).map(|x| x as u32).collect();
                if queue::current_state_is_favored(&mut self.state, &mut self.corpus) {
                    self.state.new_coverage = true;
                }
            }

            if let Some(input_id) = self.queue.add_if_interesting(&mut self.corpus, &self.state) {
                self.update_input_metadata(input_id);
                self.last_find = self.execs;
            }
        } else {
            // If a crashing input contains unseen coverage, keep track of it in the input corpus
            // but mark it as crashing and do not update the coverage bitmap and queue (because we
            // want find & save a non-crashing seed to continue with).
            //
            // This is useful for identifying blocks only reachable by crashes.
            if self.state.new_coverage {
                let mut new_coverage = false;
                for bit in &self.state.new_bits {
                    new_coverage |= self.crash_coverage_bits.insert(*bit);
                }
                if new_coverage {
                    let input_id = self.corpus.add(&self.state);
                    self.update_input_metadata(input_id);
                }
            }
        }

        // Clear logged mutation events.
        self.state.mutation_kinds.clear();

        if matches!(crash_kind, CrashKind::Halt) {
            return Ok(());
        }

        if !is_potential_crash {
            let should_save_crash = cfi_crash_info.is_some()
                || (config::enable_multifuzz_crash_detection() && crash_kind.is_crash())
                || crash_kind.is_hang(); 

            if should_save_crash {
                let text_range = self.crash_dedup_text_range();
                let is_cfi_validated = if let Some((last_addr, current_addr, _)) = cfi_crash_info {
                    self.validated_crashes
                        .lock()
                        .ok()
                        .map(|v| v.contains(&(last_addr, current_addr)))
                        .unwrap_or(false)
                } else {
                    false
                };
                let crash_type = if cfi_crash_info.is_some() {
                    if is_cfi_validated {
                        Some(CrashType::Validated)
                    } else {
                        Some(CrashType::CfiViolation)
                    }
                } else if config::enable_multifuzz_crash_detection() && crash_kind.is_crash() {
                    Some(CrashType::Native)
                } else {
                    None
                };

                if let Some(key) =
                    self.crash_logger
                        .add_if_new(&mut self.vm, &self.state, text_range, crash_type)
                {
                    if self.global.is_worker_instance() {
                        // Send this input to the main process to save and analyze.
                        // Note: hangs will already be sent if they are interesting in the code above.
                        if cfi_crash_info.is_some() {
                            tracing::warn!("sending new CFI crash to main process");
                            self.global.add_for_main(self.state.input.clone());
                        } else if config::enable_multifuzz_crash_detection()
                            && crash_kind.is_crash()
                        {
                            tracing::warn!("sending new MultiFuzz crash to main process");
                            self.global.add_for_main(self.state.input.clone());
                        } else if crash_kind.is_hang() {
                            tracing::warn!("sending new hang to main process");
                            self.global.add_for_main(self.state.input.clone());
                        }
                    } else if self.global.add_crash_or_hang(key.clone(), crash_kind) {
                        self.crash_logger.save(
                            &self.state,
                            &mut self.vm,
                            &self.target,
                            exit,
                            cfi_crash_info,
                            is_cfi_validated,
                            Some(key.as_str()),
                        )?;
                    }
                }
            }
        }

        if config::VALIDATE_CRASHES {
            tracing::info!("validating crash/hang");
            debugging::validate_last_exec(self, exit);
        }

        Ok(())
    }

    fn trace_new_bits(&mut self) {
        if let Some(block_cov) = self
            .coverage
            .as_any()
            .downcast_ref::<coverage::BlockCoverage>()
        {
            let blocks = block_cov.blocks_for(&mut self.vm, &self.state.new_bits);
            tracing::trace!("New coverage: {blocks:x?} (bits={:?})", self.state.new_bits);
        } else {
            tracing::trace!("New coverage: (bits={:?})", self.state.new_bits);
        }
    }

    fn update_input_metadata(&mut self, id: InputId) {
        let depth = if let Some(parent_id) = self.input_id {
            if parent_id < self.corpus.inputs() {
                self.corpus[parent_id].metadata.depth + 1
            } else {
                0 
            }
        } else {
            0
        };

        let metadata = &mut self.corpus[id].metadata;
        metadata.parent_id = self.state.parent;
        metadata.coverage_bits = self.state.coverage_bits;
        metadata.instructions = self.state.instructions;
        metadata.depth = depth;
        metadata.len = self.state.input.total_bytes() as u64;
        metadata.streams = self.state.input.count_non_empty_streams() as u64;
        metadata.new_bits = self.state.new_bits.clone();
        metadata.stage = self.stage;
        metadata.is_crashing = self.state.effective_is_crashing;
        metadata.is_hang = self.state.was_hang();
        metadata
            .mutation_kinds
            .clone_from(&self.state.mutation_kinds);
        metadata
            .learned_cfg_edges
            .clone_from(&self.state.learned_cfg_edges);
    }

    fn update_stats(&mut self, stats: &mut monitor::LocalStats) {
        stats.update(self);

        if let Some(id) = self.input_id {
            if id < self.corpus.inputs() {
                let metadata = &mut self.corpus[id].metadata;
                metadata.time += self.state.exec_time;
                metadata.execs += 1;
                metadata.max_find_gap =
                    u64::max(metadata.max_find_gap, metadata.execs - metadata.last_find);
                if self.state.effective_is_crashing {
                    metadata.crashes += 1;
                }
                if self.state.was_hang() {
                    metadata.hangs += 1;
                }
                if self.state.new_coverage {
                    metadata.finds += 1;
                    metadata.last_find = metadata.execs;
                }
            }
        }
    }

    fn reset_input_cursor(&mut self) -> anyhow::Result<()> {
        self.state.input.seek_to_start();
        Ok(())
    }

    fn write_input_to_target(&mut self) -> anyhow::Result<()> {
        let source = self
            .target
            .get_mmio_handler(&mut self.vm)
            .ok_or_else(|| anyhow::format_err!("target does not support MultiStream input"))?;
        source.clone_from(&self.state.input);
        Ok(())
    }

    fn auto_trim_input(&mut self) -> anyhow::Result<()> {
        let source = self
            .target
            .get_mmio_handler(&mut self.vm)
            .ok_or_else(|| anyhow::format_err!("target does not support MultiStream input"))?;
        if self.features.auto_trim {
            source.trim();
        }
        self.state.input.clone_from(source);
        Ok(())
    }

    fn get_extension_factor(&mut self, key: StreamKey) -> f64 {
        if !self.features.extension_factor {
            return 2.0;
        }
        self.input_id.map_or(1.0, |id| {
            if id < self.corpus.inputs() {
                self.corpus[id]
                    .stage_data::<LengthExtData>(Stage::MultiStreamExtend)
                    .extension_factor(key)
            } else {
                1.0 
            }
        })
    }

    #[allow(unused)]
    fn execs_since_last_find(&self) -> u64 {
        self.execs - self.last_find
    }
}

#[derive(
    Default, Debug, Clone, Copy, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Stage {
    #[default]
    Import,
    Havoc,
    MultiStreamExtend,
    MultiStreamExtendI2S,
    Trim,
    Colorization,
    InputToState,
}

impl Stage {
    pub fn short_name(&self) -> &'static str {
        match self {
            Stage::Import => "imp",
            Stage::Havoc => "hav",
            Stage::MultiStreamExtend => "ext",
            Stage::MultiStreamExtendI2S => "ex2",
            Stage::Trim => "trm",
            Stage::Colorization => "col",
            Stage::InputToState => "i2s",
        }
    }

    pub fn is_extension(&self) -> bool {
        matches!(self, Self::MultiStreamExtend | Self::MultiStreamExtendI2S)
    }
}

#[derive(Debug)]
pub enum StageExit {
    /// This stage is unsupported by the current fuzzing mode.
    Unsupported,
    /// The stage should be skipped
    Skip,
    /// The stage was interrupt as part of execution.
    Interrupted,
    /// An unknown error occured
    Unknown(anyhow::Error),
}

impl std::fmt::Display for StageExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported Stage"),
            Self::Skip => f.write_str("Skipped Stage"),
            Self::Interrupted => f.write_str("Interrupted Stage"),
            Self::Unknown(err) => f.write_fmt(format_args!("Unknown StageStart error: {err}")),
        }
    }
}

impl From<anyhow::Error> for StageExit {
    fn from(err: anyhow::Error) -> Self {
        Self::Unknown(err)
    }
}

pub(crate) trait FuzzerStage {
    fn run(fuzzer: &mut Fuzzer, stats: &mut monitor::LocalStats) -> anyhow::Result<StageExit>;
}

pub(crate) trait StageData {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit>
    where
        Self: Sized;
    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit>;
    fn end(&mut self, _fuzzer: &mut Fuzzer) {}
    fn after_check(&mut self, _fuzzer: &mut Fuzzer, _is_interesting: bool) {}
}

impl<S: StageData> FuzzerStage for S {
    fn run(fuzzer: &mut Fuzzer, stats: &mut monitor::LocalStats) -> anyhow::Result<StageExit> {
        let mut stage_data = match Self::start(fuzzer) {
            Ok(data) => data,
            Err(err) => match err {
                StageExit::Unknown(err) => return Err(err),
                exit => return Ok(exit),
            },
        };

        while let Some(exit) = stage_data.fuzz_one(fuzzer) {
            if fuzzer
                .vm
                .interrupt_flag
                .load(std::sync::atomic::Ordering::Relaxed)
                || matches!(exit, VmExit::Interrupted)
            {
                return Ok(StageExit::Interrupted);
            }
            fuzzer.check_exit_state(exit)?;
            stage_data.after_check(fuzzer, fuzzer.state.new_coverage);
            fuzzer.update_stats(stats);
        }

        stage_data.end(fuzzer);
        Ok(StageExit::Skip)
    }
}

#[allow(unused)]
struct DummyStage;

impl StageData for DummyStage {
    fn start(_: &mut Fuzzer) -> Result<Self, StageExit> {
        Ok(Self)
    }

    fn fuzz_one(&mut self, _: &mut Fuzzer) -> Option<VmExit> {
        None
    }
}

/// A stage that imports fuzzing inputs from other fuzzers.
struct SyncStage {
    inputs: Vec<(u64, Arc<MultiStream>)>,
    total: usize,
    interesting: usize,
    current_input_id: u64,
}

impl StageData for SyncStage {
    fn start(fuzzer: &mut Fuzzer) -> Result<Self, StageExit> {
        let mut inputs = fuzzer.global.take_all();
        if fuzzer.global.is_main_instance() && !inputs.is_empty() {
            tracing::info!("synchronizing {} inputs from other instances", inputs.len());
        }
        // Shuffle inputs to increase diversity across instances.
        inputs.shuffle(&mut fuzzer.rng);
        Ok(Self {
            total: inputs.len(),
            interesting: 0,
            inputs,
            current_input_id: 0,
        })
    }

    fn fuzz_one(&mut self, fuzzer: &mut Fuzzer) -> Option<VmExit> {
        let (id, input) = self.inputs.pop()?;
        self.current_input_id = id;

        fuzzer.input_id = Some(id as usize);

        Snapshot::restore_initial(fuzzer);
        fuzzer.state.reset();

        fuzzer.state.is_import = true;
        fuzzer.state.input.clone_from(&input);
        fuzzer.reset_input_cursor().unwrap();

        fuzzer.write_input_to_target().unwrap();
        let exit = fuzzer.execute()?;
        fuzzer.auto_trim_input().ok()?;

        Some(exit)
    }

    fn after_check(&mut self, fuzzer: &mut Fuzzer, interesting: bool) {
        if interesting {
            self.interesting += 1;
        }

        if fuzzer.global.is_main_instance() {
            // DEBUGGING:
            let bits = fuzzer.coverage.get_bits(&mut fuzzer.vm);
            let coverage_bits = count_all_bits(bits);
            tracing::info!(
                "sync {}: bits={coverage_bits}, new bits={:?}",
                self.current_input_id,
                fuzzer.state.new_bits
            );
        }
    }

    fn end(&mut self, fuzzer: &mut Fuzzer) {
        if fuzzer.global.is_main_instance() && self.total != 0 {
            tracing::info!(
                "{} out of {} inputs from external fuzzers were interesting",
                self.interesting,
                self.total
            );
        }
    }
}
const BASE_ENERGY: u64 = 100;

/// Calculates the energy to use for the current input.
fn calculate_energy(fuzzer: &mut Fuzzer) -> u64 {
    // If we have no information for the current input, just use the base energy.
    let Some(input_id) = fuzzer.input_id else {
        return BASE_ENERGY;
    };

    if input_id >= fuzzer.corpus.inputs() {
        return BASE_ENERGY; // id 超出范围，返回默认能量
    }

    if fuzzer.features.simple_energy_assignment {
        let mut energy = BASE_ENERGY;
        if fuzzer.corpus[input_id].has_unique_edge {
            energy *= 5;
        }
        return energy;
    }
    // A significant amount of paths are found early in the fuzzing process from just random bytes
    // so we assign them a smaller amount of fuzzing energy to account for this.
    if fuzzer.corpus[input_id].metadata.parent_id.is_none() {
        return BASE_ENERGY;
    }

    let mut energy = BASE_ENERGY as f64;

    // Add a bonus for inputs that reach a new edge.
    if fuzzer.corpus[input_id].has_unique_edge {
        energy *= 5.0;
    }

    // Global statistics about the fuzzing corpus which is used to help normalize our energy
    // assignment for the current target.
    let total_inputs = fuzzer.corpus.inputs() as u64;
    let average_input_size = fuzzer.corpus.metadata.total_input_bytes as u64 / total_inputs;
    let global_find_rate = total_inputs as f64 / fuzzer.execs as f64;

    let input = &fuzzer.corpus[input_id];

    // Adjust energy based on the input size since smaller inputs enable more effective mutations.
    match fuzzer.state.input.total_bytes() as f64 / average_input_size as f64 {
        x if x < 0.5 => energy *= 1.5,
        x if x < 1.0 => energy *= 1.1,
        x if x < 2.0 => energy *= 0.9,
        _ => energy *= 0.5,
    }

    // Add a bonus for deeper inputs (note: this at least partially cancels out with input size
    // adjustment.
    energy *= (1.05_f64.powi(input.metadata.depth as i32)).min(4.0);

    // Bonus for inputs that have recently found new coverage
    if (input.metadata.execs - input.metadata.last_find) < 1000 * BASE_ENERGY {
        energy *= 2.0;
    }

    // Add a slight bonus for inputs that have found more inputs than average
    let input_find_rate = input.metadata.finds as f64 / input.metadata.execs as f64;
    if input_find_rate > global_find_rate {
        energy *= 1.5;
    }

    // Add a penalty for inputs that frequently hang.
    if input.metadata.hangs as f32 / input.metadata.execs as f32 > 0.2 {
        energy *= 0.1;
    }

    energy.clamp(10.0, 100_000.0).round() as u64
}

fn cfi_persistence_thread(
    cfg_path: PathBuf,
    isr_path: PathBuf,
    learned_edges: Arc<Mutex<HashMap<u64, Vec<u64>>>>,
    false_positive_isrs: Arc<Mutex<HashSet<u64>>>,
    isr_whitelist: Option<Arc<Mutex<IsrWhitelist>>>,
    current_execs: Arc<std::sync::atomic::AtomicU64>,
    initial_cfg: Option<CfgData>,
    initial_block_metadata: Option<crate::cfg_extraction::CfgBlockMetadata>, 
) {
    let cold_start_execs = crate::config::cold_start_execs();
    const PERSIST_INTERVAL: u64 = 1800; 
    let mut cold_start_completed = false;

    loop {
        let current_execs_val = current_execs.load(std::sync::atomic::Ordering::Relaxed);

        if !cold_start_completed && (cold_start_execs == 0 || current_execs_val >= cold_start_execs)
        {
            cold_start_completed = true;
            eprintln!("[CFI Persistence] Cold start phase completed ({} execs), performing immediate update...", current_execs_val);

            let edges_snapshot = {
                let guard = learned_edges.lock().unwrap();
                guard.clone()
            };

            if !edges_snapshot.is_empty() {
                let edges_count: usize = edges_snapshot.values().map(|v| v.len()).sum();

                let mut merged_cfg = initial_cfg.clone().unwrap_or_default();
                for (child, parents) in edges_snapshot.iter() {
                    let parent_edges: Vec<(u64, EdgeAttribute)> = parents
                        .iter()
                        .map(|&p| (p, EdgeAttribute::TypeDynamicLearned))
                        .collect();
                    merged_cfg
                        .entry(*child)
                        .or_insert_with(Vec::new)
                        .extend(parent_edges);
                }

                if let Err(e) = save_cfg_with_metadata_to_file(
                    &cfg_path,
                    &merged_cfg,
                    initial_block_metadata.as_ref(),
                ) {
                    eprintln!(
                        "[CFI Persistence] ⚠ Failed to save learned edges after cold start: {}",
                        e
                    );
                } else {
                    eprintln!(
                        "[CFI Persistence] ✓ Saved {} learned edges to CFG after cold start",
                        edges_count
                    );
                    let mut guard = learned_edges.lock().unwrap();
                    guard.clear();
                }
            }

            let fp_isrs = {
                let guard = false_positive_isrs.lock().unwrap();
                guard.clone()
            };

            if !fp_isrs.is_empty() {
                if let Some(ref isr_whitelist_arc) = isr_whitelist {
                    eprintln!("[CFI Persistence] Cleaning ISR whitelist: removing {} false positive ISR addresses", fp_isrs.len());

                    {
                        let mut isr_whitelist_guard = isr_whitelist_arc.lock().unwrap();
                        let cleaned_isrs: Vec<u64> = isr_whitelist_guard
                            .iter()
                            .filter(|&addr| !fp_isrs.contains(addr))
                            .copied()
                            .collect();
                        *isr_whitelist_guard = cleaned_isrs.into_iter().collect();
                        eprintln!("[CFI Persistence] ✓ Updated in-memory ISR whitelist (removed {} false positives)", fp_isrs.len());
                    }

                    let isr_whitelist_snapshot = {
                        let guard = isr_whitelist_arc.lock().unwrap();
                        guard.clone()
                    };
                    if let Err(e) = save_isr_to_file(&isr_path, &isr_whitelist_snapshot, &fp_isrs) {
                        eprintln!(
                            "[CFI Persistence] ⚠ Failed to save cleaned ISR whitelist to file: {}",
                            e
                        );
                    } else {
                        eprintln!(
                            "[CFI Persistence] ✓ Successfully saved cleaned ISR whitelist to file"
                        );
                    }
                }
            }

            std::thread::sleep(Duration::from_secs(PERSIST_INTERVAL));
            continue;
        }

        std::thread::sleep(Duration::from_secs(PERSIST_INTERVAL));

        let edges_snapshot = {
            let guard = learned_edges.lock().unwrap();
            if guard.is_empty() {
                continue;
            }
            guard.clone()
        };

        let edges_count: usize = edges_snapshot.values().map(|v| v.len()).sum();

        let mut merged_cfg = initial_cfg.clone().unwrap_or_default();
        for (child, parents) in edges_snapshot.iter() {
            let parent_edges: Vec<(u64, EdgeAttribute)> = parents
                .iter()
                .map(|&p| (p, EdgeAttribute::TypeDynamicLearned))
                .collect();
            merged_cfg
                .entry(*child)
                .or_insert_with(Vec::new)
                .extend(parent_edges);
        }

        if let Err(e) =
            save_cfg_with_metadata_to_file(&cfg_path, &merged_cfg, initial_block_metadata.as_ref())
        {
            eprintln!("[CFI Persistence] ⚠ Failed to save learned edges: {}", e);
        } else {
            eprintln!(
                "[CFI Persistence] ✓ Saved {} learned edges to CFG",
                edges_count
            );
            let mut guard = learned_edges.lock().unwrap();
            guard.clear();
        }
    }
}
