use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Arc, Mutex,
};

use hashbrown::{HashMap, HashSet};
use icicle_vm::{
    cpu::{Cpu, Exception, ExceptionCode, HookHandler, ValueSource},
    Vm,
};
use pcode;

use crate::cfg_extraction::{CfgBlockMetadata, CfgData, IsrWhitelist};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfiCrashType {
    SoftJumpToISR,
    ROP,
    OutOfText,
    Unaligned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfiCheckResult {
    Allow,
    TrueCrash(CfiCrashType),
    PotentialCrash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionType {
    Normal,
    Call,
    Return,
}

pub struct CfiEnforcerHook {
    pub last_block: u64,
    pub init_complete: bool,

    pub shadow_stack: Vec<u64>,

    pub has_potential_crash: bool,
    pub potential_crash_info: Vec<(u64, u64)>, 
    pub true_crash_info: Option<(u64, u64, CfiCrashType)>,
    pub saved_crashes: HashSet<(u64, u64)>,

    pub local_exec_count: u64,
    pub current_execs: Arc<std::sync::atomic::AtomicU64>,

    pub local_learned_edges: HashMap<u64, Vec<u64>>,
    pub local_new_edges_count: usize,
    pub global_learned_edges: Arc<Mutex<HashMap<u64, Vec<u64>>>>,

    pub instruction_cache: HashMap<u64, (InstructionType, u8)>,

    pub bitmap: Arc<Vec<AtomicU8>>,
    pub cfg_data: Option<Arc<CfgData>>, 
    pub block_metadata: Option<Arc<CfgBlockMetadata>>, 
    pub isr_whitelist: Option<Arc<Mutex<IsrWhitelist>>>,
    pub text_range: Option<(u64, u64)>,

    pub false_positive_isrs: Arc<Mutex<HashSet<u64>>>,

    pub enabled: bool,
    pub xpsr_reg_var: Option<pcode::VarNode>,

    pub perf_stats: PerfStats,
}

#[derive(Default)]
pub struct PerfStats {
    pub try_lock_failures: AtomicU64,
    pub try_lock_successes: AtomicU64,
    pub forced_lock_count: AtomicU64, 

    pub sync_calls: AtomicU64,
    pub sync_total_time_us: AtomicU64, 
    pub max_buffer_size: AtomicUsize,

    pub add_edge_calls: AtomicU64,

    pub fast_path_hits: AtomicU64,  
    pub slow_path_calls: AtomicU64, 

    pub transitions_observed: AtomicU64,
    pub filter_allowed: AtomicU64,
    pub immediate_violations: AtomicU64,
    pub suspicious_flagged: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub struct PerfStatsSnapshot {
    pub try_lock_failures: u64,
    pub try_lock_successes: u64,
    pub forced_lock_count: u64,
    pub sync_calls: u64,
    pub sync_total_time_us: u64,
    pub max_buffer_size: usize,
    pub add_edge_calls: u64,
    pub current_buffer_size: usize,
    pub fast_path_hits: u64,
    pub slow_path_calls: u64,
    pub transitions_observed: u64,
    pub filter_allowed: u64,
    pub immediate_violations: u64,
    pub suspicious_flagged: u64,
}

impl CfiEnforcerHook {
    pub fn new() -> Self {
        const BITMAP_SIZE: usize = 65536;
        let bitmap = Arc::new((0..BITMAP_SIZE).map(|_| AtomicU8::new(0)).collect());

        Self {
            last_block: 0,
            init_complete: false,
            shadow_stack: Vec::new(),
            has_potential_crash: false,
            potential_crash_info: Vec::new(), 
            true_crash_info: None,
            saved_crashes: HashSet::new(),
            local_exec_count: 0,
            local_learned_edges: HashMap::new(),
            local_new_edges_count: 0,
            global_learned_edges: Arc::new(Mutex::new(HashMap::new())),
            instruction_cache: HashMap::new(),
            bitmap,
            cfg_data: None,
            block_metadata: None,
            isr_whitelist: None,
            text_range: None,
            false_positive_isrs: Arc::new(Mutex::new(HashSet::new())),
            enabled: false,
            xpsr_reg_var: None,
            current_execs: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            perf_stats: PerfStats::default(),
        }
    }

    fn initialize_with_xpsr(
        &mut self,
        xpsr_reg_var: Option<pcode::VarNode>,
        cfg_data: Option<CfgData>,
        block_metadata: Option<CfgBlockMetadata>, 
        isr_whitelist: Option<IsrWhitelist>,
        text_range: Option<(u64, u64)>,
        current_execs: Arc<std::sync::atomic::AtomicU64>,
    ) -> anyhow::Result<()> {
        self.current_execs = current_execs;
        self.cfg_data = cfg_data.map(Arc::new);
        self.block_metadata = block_metadata.map(Arc::new);
        self.isr_whitelist = isr_whitelist.map(|wl| Arc::new(Mutex::new(wl)));
        self.text_range = text_range;
        self.xpsr_reg_var = xpsr_reg_var;

        let mut edges_count = 0;
        let mut blocks_count = 0;
        if let Some(ref cfg) = self.cfg_data {
            blocks_count = cfg.len();
            for (dest_addr, pred_edges) in cfg.as_ref() {
                for (pred_addr, _attr) in pred_edges {
                    edges_count += 1;
                    let (_, byte_idx, bit_idx) = calculate_edge_hash(*pred_addr, *dest_addr);
                    let bitmap_byte = &self.bitmap[byte_idx];
                    let mut current = bitmap_byte.load(Ordering::Relaxed);
                    current |= 1 << bit_idx;
                    bitmap_byte.store(current, Ordering::Relaxed);
                }
            }
            eprintln!(
                "[CFI] ✓ Bitmap initialized: {} edges from {} basic blocks in CFG",
                edges_count, blocks_count
            );
        } else {
            eprintln!("[CFI] ⚠ Warning: cfg_data is None, bitmap will be empty! All edges will go through slow-path!");
        }

        self.init_complete = true;
        self.enabled = true;

        Ok(())
    }

    pub fn call_hook(&mut self, cpu: &mut Cpu, current_addr: u64) {
        if !self.enabled || !self.init_complete {
            return;
        }

        let last_addr = self.last_block;
        if last_addr == 0 || last_addr == u64::MAX || last_addr == current_addr {
            self.last_block = current_addr;
            return;
        }

        self.last_block = current_addr;
        self.local_exec_count += 1;
        self.perf_stats
            .transitions_observed
            .fetch_add(1, Ordering::Relaxed);

        let (hash, byte_idx, bit_idx) = calculate_edge_hash(last_addr, current_addr);

        let bitmap_byte = self.bitmap[byte_idx].load(Ordering::Relaxed);
        if (bitmap_byte >> bit_idx) & 1 == 1 {
            self.perf_stats
                .fast_path_hits
                .fetch_add(1, Ordering::Relaxed);
            return;  
        }

        self.perf_stats
            .slow_path_calls
            .fetch_add(1, Ordering::Relaxed);
        let cold_start_execs = crate::config::cold_start_execs();
        let current_execs = self.current_execs.load(Ordering::Relaxed);
        if cold_start_execs > 0 && current_execs < cold_start_execs {
            match cfi_check_pipeline(self, cpu, last_addr, current_addr, hash, byte_idx, bit_idx) {
                CfiCheckResult::Allow => {
                    self.perf_stats
                        .filter_allowed
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                CfiCheckResult::TrueCrash(crash_type) => {
                    self.perf_stats
                        .immediate_violations
                        .fetch_add(1, Ordering::Relaxed);
                    self.true_crash_info = Some((last_addr, current_addr, crash_type));
                    cpu.exception = Exception::new(ExceptionCode::Environment, current_addr);
                    return;
                }
                CfiCheckResult::PotentialCrash => {
                    self.perf_stats
                        .filter_allowed
                        .fetch_add(1, Ordering::Relaxed);
                    learn_edge_with_hash(self, last_addr, current_addr, hash, byte_idx, bit_idx);
                    return;
                }
            }
        }

        match cfi_check_pipeline(self, cpu, last_addr, current_addr, hash, byte_idx, bit_idx) {
            CfiCheckResult::Allow => {
                self.perf_stats
                    .filter_allowed
                    .fetch_add(1, Ordering::Relaxed);
            }
            CfiCheckResult::TrueCrash(crash_type) => {
                self.perf_stats
                    .immediate_violations
                    .fetch_add(1, Ordering::Relaxed);
                self.true_crash_info = Some((last_addr, current_addr, crash_type));
                cpu.exception = Exception::new(ExceptionCode::Environment, current_addr);
            }
            CfiCheckResult::PotentialCrash => {
                let edge_key = (last_addr, current_addr);
                if self.saved_crashes.insert(edge_key) {
                    self.perf_stats
                        .suspicious_flagged
                        .fetch_add(1, Ordering::Relaxed);
                    self.has_potential_crash = true;
                    self.potential_crash_info.push(edge_key); 
                    eprintln!(
                        "[CFI] ☠️ Trapped UNIQUE Potential Crash: 0x{:x} -> 0x{:x} (optimistic execution: allowing continue)",
                        last_addr, current_addr
                    );
                }
            }
        }
    }

    pub fn reset_execution_state(&mut self) {
        self.shadow_stack.clear();
        self.last_block = 0;
        self.has_potential_crash = false;
        self.potential_crash_info.clear(); 
    }

    pub fn update_exec_count(&mut self, execs: u64) {
        self.local_exec_count = execs;
        self.current_execs
            .store(execs, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn post_exec_sync(&mut self) {
        if self.local_new_edges_count == 0 {
            return;
        }

        let sync_start = std::time::Instant::now();
        self.perf_stats.sync_calls.fetch_add(1, Ordering::Relaxed);

        let current_size = self.local_new_edges_count;
        let max_size = self.perf_stats.max_buffer_size.load(Ordering::Relaxed);
        if current_size > max_size {
            self.perf_stats
                .max_buffer_size
                .store(current_size, Ordering::Relaxed);
        }

        if let Ok(mut global) = self.global_learned_edges.try_lock() {
            self.perf_stats
                .try_lock_successes
                .fetch_add(1, Ordering::Relaxed);

            for (child, parents) in self.local_learned_edges.drain() {
                global.entry(child).or_insert_with(Vec::new).extend(parents);
            }
            self.local_new_edges_count = 0;
        } else {
            self.perf_stats
                .try_lock_failures
                .fetch_add(1, Ordering::Relaxed);

            if self.local_new_edges_count > 10000 {
                self.perf_stats
                    .forced_lock_count
                    .fetch_add(1, Ordering::Relaxed);
                let mut global = self.global_learned_edges.lock().unwrap();
                for (child, parents) in self.local_learned_edges.drain() {
                    global.entry(child).or_insert_with(Vec::new).extend(parents);
                }
                self.local_new_edges_count = 0;
            }
        }

        let sync_duration_us = sync_start.elapsed().as_micros() as u64;
        self.perf_stats
            .sync_total_time_us
            .fetch_add(sync_duration_us, Ordering::Relaxed);
    }

    pub fn add_learned_edge(&mut self, src: u64, dst: u64) {
        self.perf_stats
            .add_edge_calls
            .fetch_add(1, Ordering::Relaxed);

        let (_, byte_idx, bit_idx) = calculate_edge_hash(src, dst);
        let bitmap_byte = &self.bitmap[byte_idx];
        let mut current = bitmap_byte.load(Ordering::Relaxed);
        current |= 1 << bit_idx;
        bitmap_byte.store(current, Ordering::Relaxed);

        self.local_learned_edges
            .entry(dst)
            .or_insert_with(Vec::new)
            .push(src);
        self.local_new_edges_count += 1;

    }

    pub fn get_perf_stats(&self) -> PerfStatsSnapshot {
        PerfStatsSnapshot {
            try_lock_failures: self.perf_stats.try_lock_failures.load(Ordering::Relaxed),
            try_lock_successes: self.perf_stats.try_lock_successes.load(Ordering::Relaxed),
            forced_lock_count: self.perf_stats.forced_lock_count.load(Ordering::Relaxed),
            sync_calls: self.perf_stats.sync_calls.load(Ordering::Relaxed),
            sync_total_time_us: self.perf_stats.sync_total_time_us.load(Ordering::Relaxed),
            max_buffer_size: self.perf_stats.max_buffer_size.load(Ordering::Relaxed),
            add_edge_calls: self.perf_stats.add_edge_calls.load(Ordering::Relaxed),
            current_buffer_size: self.local_new_edges_count,
            fast_path_hits: self.perf_stats.fast_path_hits.load(Ordering::Relaxed),
            slow_path_calls: self.perf_stats.slow_path_calls.load(Ordering::Relaxed),
            transitions_observed: self.perf_stats.transitions_observed.load(Ordering::Relaxed),
            filter_allowed: self.perf_stats.filter_allowed.load(Ordering::Relaxed),
            immediate_violations: self.perf_stats.immediate_violations.load(Ordering::Relaxed),
            suspicious_flagged: self.perf_stats.suspicious_flagged.load(Ordering::Relaxed),
        }
    }

    pub fn remove_learned_edge(&mut self, src: u64, dst: u64) {
        let (_, byte_idx, bit_idx) = calculate_edge_hash(src, dst);
        let bitmap_byte = &self.bitmap[byte_idx];
        let mut current = bitmap_byte.load(Ordering::Relaxed);
        current &= !(1 << bit_idx);
        bitmap_byte.store(current, Ordering::Relaxed);

        let mut global = self.global_learned_edges.lock().unwrap();
        if let Some(parents) = global.get_mut(&dst) {
            parents.retain(|&p| p != src);
            if parents.is_empty() {
                global.remove(&dst);
            }
        }

        if let Some(parents) = self.local_learned_edges.get_mut(&dst) {
            parents.retain(|&p| p != src);
            if parents.is_empty() {
                self.local_learned_edges.remove(&dst);
            }
        }
    }
}

fn calculate_edge_hash(last_addr: u64, current_addr: u64) -> (usize, usize, usize) {
    const HASH_MASK: usize = 0x7FFFF; 
    let hash = ((last_addr >> 1) ^ current_addr) as usize & HASH_MASK;
    let byte_idx = hash / 8;
    let bit_idx = hash % 8;
    (hash, byte_idx, bit_idx)
}

fn is_interrupt_active(cpu: &mut Cpu, xpsr_reg_var: Option<pcode::VarNode>) -> bool {
    if let Some(xpsr_var) = xpsr_reg_var {
        let xpsr = cpu.read_var::<u32>(xpsr_var);
        let exception_number = xpsr & 0x1ff;
        exception_number > 0
    } else {
        false
    }
}

fn learn_edge_with_hash(
    data: &mut CfiEnforcerHook,
    last_addr: u64,
    current_addr: u64,
    _hash: usize,
    byte_idx: usize,
    bit_idx: usize,
) {
    let bitmap_byte = &data.bitmap[byte_idx];
    let mut current = bitmap_byte.load(Ordering::Relaxed);
    current |= 1 << bit_idx;
    bitmap_byte.store(current, Ordering::Relaxed);

    data.local_learned_edges
        .entry(current_addr) 
        .or_insert_with(Vec::new)
        .push(last_addr);
    data.local_new_edges_count += 1;
}

fn cfi_check_pipeline(
    data: &mut CfiEnforcerHook,
    cpu: &mut Cpu,
    last_addr: u64,
    current_addr: u64,
    hash: usize,
    byte_idx: usize,
    bit_idx: usize,
) -> CfiCheckResult {
    let is_interrupt = is_interrupt_active(cpu, data.xpsr_reg_var);
    if let Some(ref isr_whitelist) = data.isr_whitelist {
        let isr_whitelist_guard = isr_whitelist.lock().unwrap();
        if isr_whitelist_guard.contains(&current_addr) {
            drop(isr_whitelist_guard);

            if is_interrupt {
                return CfiCheckResult::Allow; 
            } else {
                log_cfi_violation(data, last_addr, current_addr, "Soft jump to ISR");
                return CfiCheckResult::TrueCrash(CfiCrashType::SoftJumpToISR);
            }
        }
    }

    if is_exc_return(current_addr) {
        return CfiCheckResult::Allow;
    }

    if let Some(result) = check_shadow_stack(data, cpu, last_addr, current_addr) {
        return result;
    }

    if let Some((text_base, text_end)) = data.text_range {
        let is_in_text = current_addr >= text_base && current_addr < text_end;
        let is_aligned = current_addr % 2 == 0; 

        if !is_in_text || !is_aligned {
            let (reason, crash_type) = if !is_in_text {
                (
                    format!("Target address 0x{:x} not in .text section", current_addr),
                    CfiCrashType::OutOfText,
                )
            } else {
                (
                    format!("Target address 0x{:x} not properly aligned", current_addr),
                    CfiCrashType::Unaligned,
                )
            };
            log_cfi_violation(data, last_addr, current_addr, &reason);
            return CfiCheckResult::TrueCrash(crash_type);
        }
    }

    if let Some(ref metadata_map) = data.block_metadata {
        let last_clean = last_addr & !1;
        let current_clean = current_addr & !1;

        if let Some(metadata) = metadata_map.as_ref().get(&last_clean) {
            let expected_next = metadata.end_pc + 2; 

            if current_clean == expected_next && !metadata.has_explicit_branch {
                learn_edge_with_hash(data, last_addr, current_addr, hash, byte_idx, bit_idx);
                return CfiCheckResult::Allow;
            }
        }
    }

    let is_learned = {
        if let Ok(global) = data.global_learned_edges.try_lock() {
            global
                .get(&current_addr)
                .map(|parents| parents.contains(&last_addr))
                .unwrap_or(false)
        } else {
            false
        }
    };

    if is_learned {
        learn_edge_with_hash(data, last_addr, current_addr, hash, byte_idx, bit_idx);
        return CfiCheckResult::Allow;
    }

    CfiCheckResult::PotentialCrash
}

fn check_shadow_stack(
    data: &mut CfiEnforcerHook,
    cpu: &mut Cpu,
    last_addr: u64,
    current_addr: u64,
) -> Option<CfiCheckResult> {
    let (mut instr_type, instr_size) = get_instruction_type_and_size(data, cpu, last_addr);

    if matches!(instr_type, InstructionType::Normal) {
        if scan_for_return(cpu, last_addr) {
            instr_type = InstructionType::Return;
        }
    }

    match instr_type {
        InstructionType::Call => {
            let next_addr = last_addr + instr_size as u64;
            data.shadow_stack.push(next_addr);

            None
        }
        InstructionType::Return => {
            if is_exc_return(current_addr) {
                return Some(CfiCheckResult::Allow);
            }


            let is_in_isr = is_interrupt_active(cpu, data.xpsr_reg_var);
            if is_in_isr {
                return Some(CfiCheckResult::Allow);
            }
            match data.shadow_stack.pop() {
                Some(expected) => {
                    if current_addr != expected {
                        log_cfi_violation(data, last_addr, current_addr, "ROP detected");
                        return Some(CfiCheckResult::TrueCrash(CfiCrashType::ROP));
                    }
                    return Some(CfiCheckResult::Allow);
                }
                None => {
                    return Some(CfiCheckResult::Allow);
                }
            }
        }
        _ => {
            None
        }
    }
}

fn get_instruction_type_and_size(
    data: &mut CfiEnforcerHook,
    cpu: &mut Cpu,
    addr: u64,
) -> (InstructionType, u8) {
    const MAX_CACHE_SIZE: usize = 10000;

    if data.instruction_cache.len() >= MAX_CACHE_SIZE {
        let to_remove = MAX_CACHE_SIZE / 2;
        let keys: Vec<u64> = data
            .instruction_cache
            .keys()
            .take(to_remove)
            .copied()
            .collect();
        for key in keys {
            data.instruction_cache.remove(&key);
        }
    }

    *data.instruction_cache.entry(addr).or_insert_with(|| {
        let instr_bytes = match cpu.mem.read_u16(addr, icicle_vm::cpu::mem::perm::NONE) {
            Ok(bytes) => bytes,
            Err(_) => return (InstructionType::Normal, 2),
        };

        if (instr_bytes & 0xF800) == 0xF000 || (instr_bytes & 0xF800) == 0xE800 {
            if let Ok(instr32) = cpu.mem.read_u32(addr, icicle_vm::cpu::mem::perm::NONE) {
                detect_instruction_type_thumb2(instr32)
            } else {
                (InstructionType::Normal, 4)
            }
        } else {
            detect_instruction_type_thumb(instr_bytes)
        }
    })
}

fn detect_instruction_type_thumb(instr: u16) -> (InstructionType, u8) {
    if instr == 0x4770 {
        return (InstructionType::Return, 2);
    }

    if (instr & 0xFF00) == 0xBD00 {
        return (InstructionType::Return, 2);
    }

    if instr == 0x46F7 {
        return (InstructionType::Return, 2);
    }

    if (instr & 0xF800) == 0xF000 {
        return (InstructionType::Call, 2);
    }

    (InstructionType::Normal, 2)
}
fn detect_instruction_type_thumb2(instr: u32) -> (InstructionType, u8) {
    let low16 = instr as u16;
    let high16 = (instr >> 16) as u16;

    if (high16 & 0xF800) == 0xF000 && (low16 & 0xF800) == 0xF800 {
        return (InstructionType::Call, 4);
    }

    (InstructionType::Normal, 4)
}

fn is_exc_return(addr: u64) -> bool {
    const EXC_RETURN_MASK: u32 = 0xffffff80;
    let addr32 = addr as u32;
    (addr32 & EXC_RETURN_MASK) == EXC_RETURN_MASK
}

#[allow(dead_code)]
fn is_bx_lr_instruction(cpu: &mut Cpu, addr: u64) -> bool {
    if let Ok(instr_bytes) = cpu.mem.read_u16(addr, icicle_vm::cpu::mem::perm::NONE) {
        instr_bytes == 0x4770
    } else {
        false
    }
}

#[allow(dead_code)]
fn is_pop_pc_instruction(cpu: &mut Cpu, addr: u64) -> bool {
    if let Ok(instr_bytes) = cpu.mem.read_u16(addr, icicle_vm::cpu::mem::perm::NONE) {
        (instr_bytes & 0xFF00) == 0xBD00
    } else {
        false
    }
}

fn scan_for_return(cpu: &mut Cpu, start_addr: u64) -> bool {
    let mut offset = 0;
    const MAX_SCAN_BYTES: u64 = 128; 

    while offset < MAX_SCAN_BYTES {
        let addr = start_addr + offset;

        let Ok(instr) = cpu.mem.read_u16(addr, icicle_vm::cpu::mem::perm::NONE) else {
            break;
        };

        if (instr & 0xFF00) == 0xBD00 {
            return true;
        }

        if instr == 0x4770 {
            return true;
        }

        if instr == 0xE8BD {
            if let Ok(suffix) = cpu.mem.read_u16(addr + 2, icicle_vm::cpu::mem::perm::NONE) {
                if (suffix & 0x8000) != 0 {
                    return true;
                }
            }
            offset += 4;
            continue;
        }

        offset += 2;
    }

    false
}

fn log_cfi_violation(_data: &mut CfiEnforcerHook, last_addr: u64, current_addr: u64, reason: &str) {
    eprintln!(
        "[CFI] ✗ Violation: 0x{:x} -> 0x{:x} ({})",
        last_addr, current_addr, reason
    );
}

impl HookHandler for CfiEnforcerHook {
    fn call(data: &mut Self, cpu: &mut Cpu, addr: u64) {
        data.call_hook(cpu, addr);
    }
}

pub fn add_cfi_hook(vm: &mut Vm) -> anyhow::Result<CfiHookRef> {
    let cfi_hook = CfiEnforcerHook::new();
    let hook_id = vm.cpu.add_hook(cfi_hook);
    icicle_vm::injector::register_block_hook_injector(vm, 0, u64::MAX, hook_id);
    Ok(CfiHookRef(hook_id))
}

#[derive(Copy, Clone)]
pub struct CfiHookRef(pcode::HookId);

impl CfiHookRef {
    pub fn get_mut<'a>(&self, vm: &'a mut Vm) -> Option<&'a mut CfiEnforcerHook> {
        vm.cpu.get_hook_mut(self.0).data_mut::<CfiEnforcerHook>()
    }

    pub fn get_perf_stats(&self, vm: &mut Vm) -> Option<PerfStatsSnapshot> {
        self.get_mut(vm).map(|cfi| cfi.get_perf_stats())
    }

    pub fn initialize(
        &self,
        vm: &mut Vm,
        cfg_data: Option<CfgData>,
        block_metadata: Option<CfgBlockMetadata>, 
        isr_whitelist: Option<IsrWhitelist>,
        text_range: Option<(u64, u64)>,
        current_execs: Arc<std::sync::atomic::AtomicU64>,
    ) -> anyhow::Result<()> {
        let xpsr_reg_var = vm.cpu.arch.sleigh.get_reg("xpsr").map(|r| r.var);

        if let Some(cfi) = self.get_mut(vm) {
            cfi.initialize_with_xpsr(
                xpsr_reg_var,
                cfg_data,
                block_metadata,
                isr_whitelist,
                text_range,
                current_execs,
            )?;
        }
        Ok(())
    }

    pub fn reset_execution_state(&self, vm: &mut Vm) {
        if let Some(cfi) = self.get_mut(vm) {
            cfi.reset_execution_state();
        }
    }

    pub fn has_potential_crash(&self, vm: &mut Vm) -> bool {
        self.get_mut(vm)
            .map(|cfi| cfi.has_potential_crash)
            .unwrap_or(false)
    }

    pub fn get_potential_crashes(&self, vm: &mut Vm) -> Vec<(u64, u64)> {
        self.get_mut(vm)
            .map(|cfi| cfi.potential_crash_info.clone())
            .unwrap_or_default()
    }

    #[deprecated(note = "Use get_potential_crashes instead")]
    pub fn get_potential_crash(&self, vm: &mut Vm) -> Option<(u64, u64)> {
        self.get_mut(vm)?.potential_crash_info.first().copied()
    }

    pub fn get_true_crash(&self, vm: &mut Vm) -> Option<(u64, u64, CfiCrashType)> {
        self.get_mut(vm)?.true_crash_info
    }

    pub fn update_exec_count(&self, vm: &mut Vm, execs: u64) {
        if let Some(cfi) = self.get_mut(vm) {
            cfi.update_exec_count(execs);
        }
    }

    pub fn post_exec_sync(&self, vm: &mut Vm) {
        if let Some(cfi) = self.get_mut(vm) {
            cfi.post_exec_sync();
        }
    }

    pub fn get_isr_whitelist(&self, vm: &mut Vm) -> Option<Arc<Mutex<IsrWhitelist>>> {
        self.get_mut(vm)?.isr_whitelist.clone()
    }
}
