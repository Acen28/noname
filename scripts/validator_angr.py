#!/usr/bin/env python3


import angr
import claripy
import json
import sys
import os
import signal
import traceback
import time
import logging

for logger in ['angr', 'cle', 'pyvex', 'claripy', 'archinfo', 'z3']:
    logging.getLogger(logger).setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.CRITICAL)

sys.setrecursionlimit(50000)

_global_log_file = None

_project_cache = {}

_stats = {
    "invocations": 0,
    "total_latency_sec": 0.0,
    "max_latency_sec": 0.0,
    "max_validjump_latency_sec": 0.0,
    "max_truecrash_latency_sec": 0.0,
    "validjump_count": 0,
    "truecrash_count": 0,
    "unknown_count": 0,
    "validjump_latency_sum_sec": 0.0,
    "truecrash_latency_sum_sec": 0.0,
    "unknown_latency_sum_sec": 0.0,
}

def get_log_file():
    """获取全局日志文件句柄，如果不存在则创建"""
    global _global_log_file
    if _global_log_file is None:
        log_path = os.environ.get("VALIDATOR_LOG_FILE")
        if log_path:
            try:
                log_dir = os.path.dirname(log_path)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                _global_log_file = open(log_path, "a", buffering=1)
            except Exception as e:
                _global_log_file = None
    return _global_log_file

def log(msg):
    """全局日志函数，只写入日志文件，不写入 stderr"""
    log_file = get_log_file()
    if log_file:
        try:
            print(msg, file=log_file, flush=True)
        except Exception:
            pass  

def get_or_load_project(firmware_path):
    """获取或加载 Angr Project 对象（带缓存）"""
    global _project_cache
    
    if firmware_path not in _project_cache:
        log(f"[Angr] Loading Angr project from {firmware_path} (first time, will cache)...")
        try:
            proj = angr.Project(firmware_path, auto_load_libs=False)
            _project_cache[firmware_path] = proj
            log(f"[Angr] ✓ Angr project loaded and cached: {firmware_path}")
        except Exception as e:
            error_msg = f"[Angr] Failed to load Angr project: {e}"
            log(error_msg)
            raise
    else:
        log(f"[Angr] Using cached Angr project: {firmware_path}")
    
    return _project_cache[firmware_path]

def create_mmio_hook(state, mmio_access_log, mmio_ranges):
    """
    抽象的 MMIO 污点源注入
    任何 MMIO 读取都返回一个符号变量 (Taint Source)
    """
    mmio_to_input = {}
    for mmio_addr, stream_key, offset, size in mmio_access_log:
        if mmio_addr not in mmio_to_input:
            mmio_to_input[mmio_addr] = []
        mmio_to_input[mmio_addr].append((stream_key, offset, size))
    
    final_ranges = []
    if mmio_ranges:
        if isinstance(mmio_ranges[0], int):  
            final_ranges = [mmio_ranges]
        else:
            final_ranges = mmio_ranges
    
    if not final_ranges:
        final_ranges = [(0x40000000, 0x60000000), (0xE0000000, 0xE0100000)]

    def hook_mmio_read(state):
        if hasattr(state.inspect, 'mem_read_address'):
            try:
                addr = state.solver.eval_one(state.inspect.mem_read_address)
            except:
                return  
            
            is_mmio = False
            for start, end in final_ranges:
                if start <= addr < end:
                    is_mmio = True
                    break
            
            if is_mmio:
                read_len = state.inspect.mem_read_length
                if read_len is None:
                    read_len = 4
                
                if addr in mmio_to_input:
                    stream_key, offset, size = mmio_to_input[addr][0]
                    sym = state.solver.BVS(f"taint_input_{stream_key}_{offset}", read_len * 8)
                else:
                    sym = state.solver.BVS(f"taint_unknown_{hex(addr)}", read_len * 8)
                
                state.inspect.mem_read_expr = sym

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=hook_mmio_read)

def install_memory_safety_hooks(state, text_range, ram_ranges):
    """
    安装内存安全检测 Hook，检测 Silent Memory Corruption
    检测：
    1. 写入 Flash/Text 段（非法）
    2. 符号化 OOB 写入（超出 RAM 范围）
    """
    flash_start, flash_end = text_range if text_range else (0x08000000, 0x09000000)
    
    valid_ram_ranges = []
    if ram_ranges:
        for r in ram_ranges:
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                valid_ram_ranges.append((r[0], r[1]))
    else:
        valid_ram_ranges = [(0x20000000, 0x20100000)]
    
    def hook_mem_write(state):
        """检测内存写入是否安全"""
        try:
            write_addr_ast = state.inspect.mem_write_address
            
            if not write_addr_ast.symbolic:
                write_addr = state.solver.eval(write_addr_ast)
                if flash_start <= write_addr < flash_end:
                    log(f"[Angr] ☠️ MEMORY CORRUPTION: Write to Flash/Text segment at {hex(write_addr)}")
                    state.globals['memory_corruption_detected'] = True
                    state.globals['memory_corruption_reason'] = f'Write to Flash/Text segment at {hex(write_addr)}'
                    state.inspect.stop = True
                    return
            
            if write_addr_ast.symbolic:
                flash_constraint = claripy.And(
                    write_addr_ast >= flash_start,
                    write_addr_ast < flash_end
                )
                if state.solver.satisfiable(extra_constraints=[flash_constraint]):
                    log(f"[Angr] ☠️ MEMORY CORRUPTION: Symbolic write may target Flash/Text segment")
                    state.globals['memory_corruption_detected'] = True
                    state.globals['memory_corruption_reason'] = 'Symbolic write may target Flash/Text segment'
                    state.inspect.stop = True
                    return
                
                oob_constraints = []
                for ram_start, ram_end in valid_ram_ranges:
                    oob_constraints.append(
                        claripy.And(write_addr_ast >= ram_start, write_addr_ast < ram_end)
                    )
                
                all_valid_ranges = oob_constraints.copy()
                all_valid_ranges.append(
                    claripy.And(write_addr_ast >= flash_start, write_addr_ast < flash_end)
                )
                
                not_in_any_range = claripy.And(*[claripy.Not(c) for c in all_valid_ranges])
                if state.solver.satisfiable(extra_constraints=[not_in_any_range]):
                    log(f"[Angr] ☠️ MEMORY CORRUPTION: Symbolic write may be OOB (outside valid RAM ranges)")
                    state.globals['memory_corruption_detected'] = True
                    state.globals['memory_corruption_reason'] = 'Symbolic write may be OOB (outside valid RAM ranges)'
                    state.inspect.stop = True
                    return
                    
        except Exception as e:
            log(f"[Angr] ⚠️ Memory safety hook exception: {e}")
    
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=hook_mem_write)
    log("[Angr] Memory safety hooks installed")

def validate_crash(dump_dir, target_pc, last_addr=None):
    try:
        last_addr_val = last_addr if last_addr is not None else 0
        log(f"[Angr] ===== validate_crash called: dump_dir={dump_dir}, target_pc=0x{target_pc:x}, last_addr=0x{last_addr_val:x}")
    except Exception:
        pass
    
    _t0 = time.perf_counter()
    _impact_used = False
    _impact_timeout = False
    _impact_steps_executed = None

    def _finish_and_log(res):
        """
        Write exactly one `[AngrStats] ...` line per invocation.
        Keep it compact so it won't dominate the existing verbose logs.
        """
        global _stats
        dt = time.perf_counter() - _t0
        rtype = res.get("result_type", "Unknown")

        _stats["invocations"] += 1
        _stats["total_latency_sec"] += dt
        _stats["max_latency_sec"] = max(_stats["max_latency_sec"], dt)

        if rtype == "ValidJump":
            _stats["validjump_count"] += 1
            _stats["validjump_latency_sum_sec"] += dt
            _stats["max_validjump_latency_sec"] = max(_stats["max_validjump_latency_sec"], dt)
        elif rtype == "TrueCrash":
            _stats["truecrash_count"] += 1
            _stats["truecrash_latency_sum_sec"] += dt
            _stats["max_truecrash_latency_sec"] = max(_stats["max_truecrash_latency_sec"], dt)
        else:
            _stats["unknown_count"] += 1
            _stats["unknown_latency_sum_sec"] += dt

        avg_lat_valid = (
            _stats["validjump_latency_sum_sec"] / _stats["validjump_count"]
            if _stats["validjump_count"] > 0
            else 0.0
        )
        avg_lat_true = (
            _stats["truecrash_latency_sum_sec"] / _stats["truecrash_count"]
            if _stats["truecrash_count"] > 0
            else 0.0
        )
        log(
            f"[AngrStats] inv={_stats['invocations']} "
            f"result={rtype} latency_sec={dt:.4f} "
            f"avg_valid_sec={avg_lat_valid:.4f} avg_true_sec={avg_lat_true:.4f} "
            f"max_valid_sec={_stats['max_validjump_latency_sec']:.4f} max_true_sec={_stats['max_truecrash_latency_sec']:.4f} "
            f"impact_used={_impact_used} impact_timeout={_impact_timeout} impact_steps={_impact_steps_executed} "
            f"total_latency_sec={_stats['total_latency_sec']:.2f} max_latency_sec={_stats['max_latency_sec']:.2f}"
        )
        return res

    try:
        if last_addr is not None:
            log(f"[Angr] Starting validation: last_addr=0x{last_addr:x} -> target_pc=0x{target_pc:x}")
        else:
            log(f"[Angr] Starting validation: target=0x{target_pc:x}")
        
        log("[Angr] Loading VM state and taint info...")
        with open(os.path.join(dump_dir, "vm_state.json")) as f:
            vm_state = json.load(f)
        log("[Angr] vm_state.json loaded")
        
        with open(os.path.join(dump_dir, "taint_info.json")) as f:
            taint_info = json.load(f)
        log("[Angr] taint_info.json loaded")
        
        ram_ranges = vm_state.get("ram_ranges") or taint_info.get("ram_ranges") or []
        
        firmware_path = vm_state["firmware_path"]
        log(f"[Angr] Firmware path: {firmware_path}")
        if not os.path.exists(firmware_path):
            log(f"[Angr] ⚠️ Firmware not found: {firmware_path}")
            return _finish_and_log({"result_type": "Unknown", "targets": [], "error": "Firmware not found"})
        
        try:
            proj = get_or_load_project(firmware_path)
        except Exception as e:
            return _finish_and_log({"result_type": "Unknown", "targets": [], "error": f"Failed to load Angr project: {str(e)}"})
        
        log("[Angr] Angr project ready (from cache or newly loaded)")
        
        log("[Angr] Creating blank state...")
        state = proj.factory.blank_state()
        log("[Angr] Blank state created")
        
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        
        state.options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        state.options.add(angr.options.SIMPLIFY_REGISTER_WRITES)
        state.options.add(angr.options.SIMPLIFY_EXIT_GUARD)
        state.options.add(angr.options.SIMPLIFY_CONSTRAINTS)

        try:
            if hasattr(state.solver, '_solver') and hasattr(state.solver._solver, 'timeout'):
                state.solver._solver.timeout = 5000
        except:
            pass

        log("[Angr] Restoring registers...")
        thumb_mode = True
        def safe_set_reg(state, name, val):
            if hasattr(state.regs, name):
                setattr(state.regs, name, val)
                return True
            return False

        for reg_name, value in vm_state["registers"].items():
            if reg_name == "pc":
                if value & 1 == 0:
                    value |= 1
                state.regs.pc = value
            elif reg_name == "xpsr":
                value |= 0x01000000
                if not safe_set_reg(state, 'xpsr', value):
                    if not safe_set_reg(state, 'cpsr', value):
                        safe_set_reg(state, 'flags', value)
            elif reg_name == "sp":
                state.regs.sp = value
            elif reg_name == "lr":
                state.regs.lr = value
            elif reg_name.startswith("r"):
                reg_num = int(reg_name[1:])
                if reg_num < 13:
                    if not safe_set_reg(state, reg_name, value):
                        safe_set_reg(state, reg_name.upper(), value)
        log("[Angr] Registers restored")
        
        log(f"[Angr] Restoring {len(vm_state['memory_segments'])} memory segments...")
        for i, seg in enumerate(vm_state["memory_segments"]):
            if i > 0 and i % 50 == 0:  
                log(f"[Angr] Restoring memory segment {i}/{len(vm_state['memory_segments'])}...")
            addr = seg["start"]
            data = bytes(seg["data"])
            state.memory.store(addr, data)
        log("[Angr] Memory segments restored")
        
        log("[Angr] Creating MMIO hook...")
        mmio_ranges = vm_state.get("mmio_ranges") or taint_info.get("mmio_ranges")
        if not mmio_ranges:  
            s_range = vm_state.get("mmio_range") or taint_info.get("mmio_range")
            if s_range:
                mmio_ranges = [s_range]
        
        create_mmio_hook(state, taint_info.get("mmio_access_log", []), mmio_ranges)
        log("[Angr] MMIO hook created")
        
        safe_regions = []
        
        text_range = vm_state.get("text_range") or taint_info.get("text_range")
        
        install_memory_safety_hooks(state, text_range, ram_ranges)
        if text_range:
            safe_regions.append(tuple(text_range))
        else:
            safe_regions.append((0x08000000, 0x09000000)) 
            
        safe_regions.append((0xFFFFFF00, 0xFFFFFFFF))

        def is_safe_address(addr):
            """检查地址是否在安全区域内"""
            addr = addr & ~1  
            for start, end in safe_regions:
                if start <= addr < end:
                    return True
            return False

        def analyze_path_complexity(state):
            """
            分析路径约束的复杂度，作为辅助信号
            返回：{
                'constraint_count': int,
                'has_bitwise_ops': bool,
                'has_mmio_taint': bool,
                'complexity_score': float
            }
            """
            try:
                constraints = state.solver.constraints
                constraint_count = len(constraints)
                
                bitwise_ops = 0
                mmio_taint_count = 0
                
                for constraint in constraints:
                    constraint_str = str(constraint)
                    if any(op in constraint_str for op in ['And', 'Or', 'Xor', 'Extract', 'Concat', '__and__', '__or__', '__xor__']):
                        bitwise_ops += 1
                    if 'taint_input' in constraint_str or 'taint_unknown' in constraint_str:
                        mmio_taint_count += 1
                
                complexity_score = constraint_count * 0.1 + bitwise_ops * 0.5 + mmio_taint_count * 1.0
                
                return {
                    'constraint_count': constraint_count,
                    'has_bitwise_ops': bitwise_ops > 0,
                    'bitwise_ops_count': bitwise_ops,
                    'has_mmio_taint': mmio_taint_count > 0,
                    'mmio_taint_count': mmio_taint_count,
                    'complexity_score': complexity_score
                }
            except Exception as e:
                log(f"[Angr] ⚠️ Path complexity analysis failed: {e}")
                return {
                    'constraint_count': 0,
                    'has_bitwise_ops': False,
                    'bitwise_ops_count': 0,
                    'has_mmio_taint': False,
                    'mmio_taint_count': 0,
                    'complexity_score': 0.0
                }
        
        def check_pc_origin(state, pc_ast, text_range, mmio_ranges, ram_ranges):
            """
            检查 PC 的数据来源
            返回：{
                'source_type': 'Flash' | 'RAM' | 'Stack' | 'MMIO' | 'Unknown',
                'is_authorized': bool,
                'details': str
            }
            """
            try:
                if not pc_ast.symbolic:
                    pc_val = state.solver.eval(pc_ast)
                    if text_range and text_range[0] <= pc_val < text_range[1]:
                        return {
                            'source_type': 'Flash',
                            'is_authorized': True,
                            'details': f'Concrete PC from Flash: {hex(pc_val)}'
                        }
                    else:
                        return {
                            'source_type': 'Unknown',
                            'is_authorized': False,
                            'details': f'Concrete PC outside Flash: {hex(pc_val)}'
                        }
                
                variables = list(pc_ast.variables)
                
                mmio_vars = [v for v in variables if 'taint_input' in v or 'taint_unknown' in v]
                if mmio_vars:
                    return {
                        'source_type': 'MMIO',
                        'is_authorized': False,
                        'details': f'PC depends on MMIO taint: {mmio_vars[:3]}' 
                    }
                
                pc_str = str(pc_ast)
                
                if 'Load' in pc_str or '__getitem__' in pc_str:
                    try:
                        sp_val = state.solver.eval(state.regs.sp) if state.regs.sp.concrete else None
                    except:
                        sp_val = None
                    
                    if sp_val:
                        is_in_ram = False
                        for ram_start, ram_end in ram_ranges:
                            if ram_start <= sp_val < ram_end:
                                is_in_ram = True
                                break
                        
                        if 'sp' in pc_str.lower() or is_in_ram:
                            return {
                                'source_type': 'Stack',
                                'is_authorized': False,
                                'details': f'PC loaded from Stack (SP: {hex(sp_val) if sp_val else "unknown"}, in RAM: {is_in_ram})'
                            }
                    
                    if ram_ranges:
                        for ram_start, ram_end in ram_ranges:
                            ram_start_str = hex(ram_start)
                            if ram_start_str[:6] in pc_str:  
                                return {
                                    'source_type': 'RAM',
                                    'is_authorized': False,
                                    'details': f'PC loaded from RAM region (detected from AST pattern, RAM range: {hex(ram_start)}-{hex(ram_end)})'
                                }
                    
                    return {
                        'source_type': 'RAM',
                        'is_authorized': False,
                        'details': 'PC depends on memory load (possibly from RAM)'
                    }
                
                reg_vars = [v for v in variables if v.startswith('reg_') or v.startswith('R')]
                if reg_vars and not mmio_vars:
                    return {
                        'source_type': 'Flash',
                        'is_authorized': True,
                        'details': f'PC from register propagation: {reg_vars[:3]}'
                    }
                
                return {
                    'source_type': 'Unknown',
                    'is_authorized': False, 
                    'details': f'Cannot determine PC origin. Variables: {variables[:5]}'
                }
                
            except Exception as e:
                log(f"[Angr] ⚠️ PC origin check failed: {e}")
                return {
                    'source_type': 'Unknown',
                    'is_authorized': False,
                    'details': f'Error: {str(e)}'
                }
        
        def impact_analysis(simgr, max_steps=30, timeout_sec=10):
            """
            多步执行验证，检查后续执行是否会出现问题
            返回：{
                'crashed': bool,
                'crash_reason': str | None,
                'steps_executed': int
            }
            """
            start_time = time.time()
            steps_executed = 0
            
            try:
                for step in range(max_steps):
                    if time.time() - start_time > timeout_sec:
                        log(f"[Angr] Impact Analysis timeout after {timeout_sec}s")
                        return {
                            'crashed': False,
                            'crash_reason': None,
                            'steps_executed': steps_executed,
                            'timeout': True
                        }
                    
                    if not simgr.active:
                        if simgr.errored:
                            error_state = simgr.errored[0]
                            error_msg = str(error_state.error)
                            log(f"[Angr] Impact Analysis: Crash detected at step {step}: {error_msg}")
                            return {
                                'crashed': True,
                                'crash_reason': error_msg,
                                'steps_executed': step
                            }
                        log(f"[Angr] Impact Analysis: All states completed normally after {step} steps")
                        return {
                            'crashed': False,
                            'crash_reason': None,
                            'steps_executed': step
                        }
                    
                    simgr.step()
                    steps_executed += 1
                    
                    for state in simgr.active:
                        if state.globals.get('memory_corruption_detected', False):
                            reason = state.globals.get('memory_corruption_reason', 'Silent Memory Corruption detected')
                            log(f"[Angr] Impact Analysis: Memory corruption detected at step {step}: {reason}")
                            return {
                                'crashed': True,
                                'crash_reason': reason,
                                'steps_executed': step
                            }
                    
                    if simgr.errored:
                        error_state = simgr.errored[0]
                        error_msg = str(error_state.error)
                        
                        if any(keyword in error_msg for keyword in [
                            'SimSegfaultError', 'No bytes in memory', 'DecodeError',
                            'Invalid memory access', 'Segmentation fault'
                        ]):
                            log(f"[Angr] Impact Analysis: CRASH detected at step {step}: {error_msg}")
                            return {
                                'crashed': True,
                                'crash_reason': error_msg,
                                'steps_executed': step
                            }
                    
                    for state in simgr.active:
                        try:
                            pc_val = state.solver.eval(state.regs.pc)
                            try:
                                _ = state.memory.load(pc_val, 4)
                            except:
                                log(f"[Angr] Impact Analysis: Memory access error at step {step}, PC: {hex(pc_val)}")
                                return {
                                    'crashed': True,
                                    'crash_reason': f'Memory access error at PC {hex(pc_val)}',
                                    'steps_executed': step
                                }
                        except:
                            pass
                
                log(f"[Angr] Impact Analysis: Completed {max_steps} steps without crash")
                return {
                    'crashed': False,
                    'crash_reason': None,
                    'steps_executed': max_steps
                }
                
            except Exception as e:
                log(f"[Angr] Impact Analysis exception: {e}")
                return {
                    'crashed': True,
                    'crash_reason': f'Exception during impact analysis: {str(e)}',
                    'steps_executed': steps_executed
                }

        log(f"[Angr] Executing step from {hex(state.addr)}...")
        simgr = proj.factory.simgr(state)
        log("[Angr] Simulation manager created, starting step execution...")
        simgr.step()
        log("[Angr] Step execution completed")
        
        if simgr.active:
            for active_state in simgr.active:
                if active_state.globals.get('memory_corruption_detected', False):
                    reason = active_state.globals.get('memory_corruption_reason', 'Silent Memory Corruption detected')
                    log(f"[Angr] ☠️ CRASH: {reason}")
                    return _finish_and_log({"result_type": "TrueCrash", "targets": [], "reason": reason})

        if simgr.errored:
            err = simgr.errored[0].error
            err_msg = str(err)
            
            is_memory_error = (
                isinstance(err, angr.errors.SimSegfaultError) or
                isinstance(err, angr.errors.SimEngineError) or
                "No bytes in memory" in err_msg or
                "No bytes" in err_msg
            )
            
            if is_memory_error:
                try:
                    err_pc = simgr.errored[0].state.addr
                    if is_safe_address(err_pc):
                        clean_target = target_pc & ~1
                        log(f"[Angr] 🛡️ Valid Interrupt Return (Magic: {hex(err_pc)})")
                        return _finish_and_log({"result_type": "ValidJump", "targets": [clean_target]})
                except Exception:
                    pass

                log(f"[Angr] ☠️ CRASH: Execution failed ({err_msg})")
                return _finish_and_log({"result_type": "TrueCrash", "targets": []})
            
            log(f"[Angr] Error during step: {err_msg}")
            return _finish_and_log({"result_type": "Unknown", "targets": [], "error": err_msg})

        if simgr.active:
            next_state = simgr.active[0]
            pc_ast = next_state.regs.pc
            
            if not pc_ast.symbolic:
                val = next_state.solver.eval(pc_ast)
                if is_safe_address(val):
                    origin_info = check_pc_origin(next_state, pc_ast, text_range, mmio_ranges, ram_ranges)
                    log(f"[Angr] Concrete PC origin: {origin_info['source_type']} - {origin_info['details']}")
                    
                    if not origin_info['is_authorized']:
                        log(f"[Angr] ⚠️ Suspicious concrete PC source, triggering Impact Analysis...")
                        impact_simgr = proj.factory.simgr(next_state.copy())
                        _impact_used = True
                        impact_result = impact_analysis(impact_simgr, max_steps=30, timeout_sec=10)
                        _impact_timeout = bool(impact_result.get("timeout", False))
                        _impact_steps_executed = impact_result.get("steps_executed")
                        if impact_result['crashed']:
                            log(f"[Angr] ☠️ CRASH (Impact Analysis): {impact_result['crash_reason']}")
                            return _finish_and_log({"result_type": "TrueCrash", "targets": [], "impact_analysis": True})
                    
                    log(f"[Angr] ✓ ValidJump: Concrete PC {hex(val & ~1)} is in safe region")
                    return _finish_and_log({"result_type": "ValidJump", "targets": [val & ~1]})
                else:
                    log(f"[Angr] ☠️ CRASH: Concrete jump to unsafe address {hex(val & ~1)}")
                    return _finish_and_log({"result_type": "TrueCrash", "targets": []})
            
            else:
                log("[Angr] ⚠️ Tainted PC detected! Analyzing Control Authority...")
                
                complexity_info = analyze_path_complexity(next_state)
                log(f"[Angr] Path Complexity Analysis:")
                log(f"[Angr]   - Constraints: {complexity_info['constraint_count']}")
                log(f"[Angr]   - Bitwise ops: {complexity_info['bitwise_ops_count']} (has: {complexity_info['has_bitwise_ops']})")
                log(f"[Angr]   - MMIO taint: {complexity_info['mmio_taint_count']} (has: {complexity_info['has_mmio_taint']})")
                log(f"[Angr]   - Complexity score: {complexity_info['complexity_score']:.2f}")
                
                origin_info = check_pc_origin(next_state, pc_ast, text_range, mmio_ranges, ram_ranges)
                log(f"[Angr] PC Origin Check: {origin_info['source_type']} - {origin_info['details']}")
                
                if not origin_info['is_authorized']:
                    log(f"[Angr] ☠️ CRASH: PC sourced from {origin_info['source_type']} (Unauthorized)")
                    log(f"[Angr]   Details: {origin_info['details']}")
                    return _finish_and_log({"result_type": "TrueCrash", "targets": [], "origin_check": True})
                
                log(f"[Angr] PC sourced from {origin_info['source_type']} (Authorized)")
                
                try:
                    solutions = next_state.solver.eval_upto(pc_ast, 257)
                except Exception as e:
                    log(f"[Angr] ⚠️ Solver failed: {e}")
                    clean_target = target_pc & ~1
                    if is_safe_address(clean_target):
                        return _finish_and_log({
                            "result_type": "Unknown",
                            "targets": [],
                            "error": f"Solver error: {e}. Cannot verify tainted PC."
                        })
                    else:
                        return _finish_and_log({
                            "result_type": "TrueCrash",
                            "targets": [],
                            "reason": f"Solver error and unsafe target: {hex(clean_target)}"
                        })

                if len(solutions) > 256:
                    log("[Angr] ☠️ CRASH: PC is Unconstrained (Attacker has full control)")
                    return _finish_and_log({"result_type": "TrueCrash", "targets": []})

                valid_targets = []
                for sol in solutions:
                    if is_safe_address(sol):
                        valid_targets.append(sol & ~1)
                    else:
                        if sol != 0:  
                            log(f"[Angr] ☠️ CRASH: Tainted PC can reach unsafe address {hex(sol)}")
                            return _finish_and_log({"result_type": "TrueCrash", "targets": []})


                unique_targets = sorted(list(set(valid_targets)))

                if len(unique_targets) <= 1:
                    log(f"[Angr] ✓ ValidJump: Single target {[hex(t) for t in unique_targets]}")

                    if complexity_info['complexity_score'] > 10.0 or complexity_info['has_mmio_taint']:
                        log(f"[Angr] ⚠️ High complexity or MMIO taint detected, triggering Impact Analysis...")
                        impact_simgr = proj.factory.simgr(next_state.copy())
                        _impact_used = True
                        impact_result = impact_analysis(impact_simgr, max_steps=30, timeout_sec=10)
                        _impact_timeout = bool(impact_result.get("timeout", False))
                        _impact_steps_executed = impact_result.get("steps_executed")
                        if impact_result['crashed']:
                            log(f"[Angr] ☠️ CRASH (Impact Analysis): {impact_result['crash_reason']}")
                            return _finish_and_log({"result_type": "TrueCrash", "targets": [], "impact_analysis": True})

                    return _finish_and_log({"result_type": "ValidJump", "targets": unique_targets})

                else:
                    diffs = [unique_targets[i + 1] - unique_targets[i] for i in range(len(unique_targets) - 1)]
                    avg_diff = sum(diffs) / len(diffs) if diffs else 0

                    if avg_diff > 1024: 
                        log(f"[Angr] ☠️ SILENT CRASH CANDIDATE: Sparse Jump Targets (Avg diff: {avg_diff})")
                        log(f"[Angr] Targets: {[hex(t) for t in unique_targets]}")
                        return _finish_and_log({"result_type": "TrueCrash", "targets": []})

                    log(f"[Angr] ✓ Valid Tainted Jump (Likely Switch, Avg diff: {avg_diff})")
                    clean_expected = target_pc & ~1
                    if clean_expected not in unique_targets and is_safe_address(clean_expected):
                        unique_targets.append(clean_expected)
                        unique_targets = sorted(list(set(unique_targets)))

                    log(f"[Angr] ⚠️ Triggering Impact Analysis for symbolic PC ValidJump...")
                    impact_simgr = proj.factory.simgr(next_state.copy())
                    _impact_used = True
                    impact_result = impact_analysis(impact_simgr, max_steps=30, timeout_sec=10)
                    _impact_timeout = bool(impact_result.get("timeout", False))
                    _impact_steps_executed = impact_result.get("steps_executed")
                    if impact_result['crashed']:
                        log(f"[Angr] ☠️ CRASH (Impact Analysis): {impact_result['crash_reason']}")
                        log(f"[Angr]   Steps executed: {impact_result['steps_executed']}")
                        return _finish_and_log({"result_type": "TrueCrash", "targets": [], "impact_analysis": True})
                    else:
                        log(f"[Angr] Impact Analysis passed: {impact_result['steps_executed']} steps without crash")

                    return _finish_and_log({"result_type": "ValidJump", "targets": unique_targets})

        return _finish_and_log({"result_type": "Unknown", "targets": [], "error": "No active state"})
    
    except Exception as e:
        log(f"[Angr] Exception: {e}")
        import traceback
        traceback.print_exc(file=get_log_file() or sys.stderr)
        return _finish_and_log({"result_type": "Unknown", "targets": [], "error": str(e)})

def main():
    get_log_file()
    log("[Angr] Validator service started")
    
    print("READY", file=sys.stderr, flush=True)
    
    if hasattr(sys.stdin, 'reconfigure'):
        try:
            sys.stdin.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    
    try:
        for line in sys.stdin:
            try:
                line = line.strip()
                if not line:
                    continue

                req = json.loads(line)
                last_addr = req.get("last_addr")

                target_pc_val = req.get('target_pc', 0)
                if not isinstance(target_pc_val, int):
                    target_pc_val = int(target_pc_val) if target_pc_val else 0
                _ = last_addr if last_addr is not None else 0

                res = validate_crash(req["dump_dir"], req["target_pc"], last_addr)

                try:
                    print(json.dumps(res), flush=True)
                except (BrokenPipeError, IOError) as e:
                    if isinstance(e, IOError) and e.errno != 32:
                        raise
                    log("[Angr] Broken pipe: Rust fuzzer closed connection")
                    sys.exit(0)

            except BrokenPipeError:
                log("[Angr] Broken pipe on stdin")
                sys.exit(0)
            except Exception as e:
                try:
                    print(json.dumps({"result_type": "Unknown", "targets": [], "error": str(e)}), flush=True)
                except (BrokenPipeError, IOError) as pipe_err:
                    if isinstance(pipe_err, IOError) and pipe_err.errno != 32:
                        raise
                    log(f"[Angr] Cannot send error response (pipe closed): {pipe_err}")
                    log(f"[Angr] Original error: {e}")
                    sys.exit(0)
    except (BrokenPipeError, IOError) as e:
        if isinstance(e, IOError) and e.errno != 32:
            raise
        log("[Angr] Broken pipe on stdin loop")
        sys.exit(0)

if __name__ == "__main__":
    main()
