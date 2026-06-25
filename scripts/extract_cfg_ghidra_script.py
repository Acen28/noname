
from ghidra.app.script import GhidraScript
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import Instruction
from ghidra.program.model.address import Address
from ghidra.program.model.lang import OperandType
import json
import os
import sys

def normalize_addr(addr):
    """
    Normalize address by clearing the Thumb bit (bit 0).
    This ensures all addresses are even numbers, matching fuzzer execution addresses.
    
    Args:
        addr: Address object or integer offset
        
    Returns:
        Normalized address (even number)
    """
    if isinstance(addr, Address):
        offset = addr.getOffset()
    else:
        offset = addr
    return offset & ~1

def get_edge_attribute(block, program):
    """
    Determine edge attribute by analyzing the last instruction in the block.
    
    Returns:
        "TYPE_DIRECT_STATIC" for direct jumps (B, BL, JMP imm)
        "TYPE_INDIRECT_STATIC" for indirect jumps (BLX reg, switch tables)
    """
    try:
        # Get the last instruction in the block
        last_addr = block.getMaxAddress()
        listing = program.getListing()
        last_instr = listing.getInstructionAt(last_addr)
        
        if last_instr is None:
            # Try to get the instruction before the max address
            addr = last_addr.previous()
            last_instr = listing.getInstructionAt(addr)
        
        if last_instr is None:
            return "TYPE_DIRECT_STATIC"  # Default to direct
        
        mnemonic = last_instr.getMnemonicString().upper()
        
        # Check for indirect calls/jumps
        # BLX reg, BX reg, MOV PC, reg, etc.
        if mnemonic in ["BLX", "BX", "MOV"]:
            # Check if it's a register operand (indirect)
            num_operands = last_instr.getNumOperands()
            for i in range(num_operands):
                op_type = last_instr.getOperandType(i)
                # Check if operand is a register (not immediate)
                if (op_type & OperandType.REGISTER) != 0:
                    # Check if it's PC or LR (common in indirect jumps)
                    op_obj = last_instr.getOpObjects(i)
                    if op_obj and len(op_obj) > 0:
                        op_str = str(op_obj[0]).upper()
                        if "PC" in op_str or "LR" in op_str or "R" in op_str:
                            return "TYPE_INDIRECT_STATIC"
        
        # Check for switch tables (LDR PC, [PC, ...])
        if mnemonic == "LDR":
            num_operands = last_instr.getNumOperands()
            if num_operands >= 2:
                op0_str = str(last_instr.getOpObjects(0)).upper()
                if "PC" in op0_str:
                    return "TYPE_INDIRECT_STATIC"
        
        # Default: direct static jump
        return "TYPE_DIRECT_STATIC"
        
    except Exception as e:
        # On error, default to direct static
        return "TYPE_DIRECT_STATIC"

def check_has_explicit_branch(block, program):
    """
    Check if the basic block ends with an explicit branch instruction.
    
    Returns:
        True if the block ends with a branch/call/return instruction (B, BL, BX, POP {PC}, etc.)
        False if the block falls through to the next sequential instruction
    """
    try:
        # Get the last instruction in the block
        last_addr = block.getMaxAddress()
        listing = program.getListing()
        last_instr = listing.getInstructionAt(last_addr)
        
        if last_instr is None:
            # Try to get the instruction before the max address
            addr = last_addr.previous()
            last_instr = listing.getInstructionAt(addr)
        
        if last_instr is None:
            return False  # No instruction found, assume fall-through
        
        mnemonic = last_instr.getMnemonicString().upper()
        
        # Check for explicit branch/call/return instructions
        # B, BL, BLX, BX, POP {PC}, etc.
        branch_mnemonics = ["B", "BL", "BLX", "BX", "POP", "RET", "RETURN"]
        
        if mnemonic in branch_mnemonics:
            # For POP, check if PC is in the register list
            if mnemonic == "POP":
                num_operands = last_instr.getNumOperands()
                for i in range(num_operands):
                    op_str = str(last_instr.getOpObjects(i)).upper()
                    if "PC" in op_str:
                        return True  # POP {..., PC} is an explicit branch
            else:
                return True  # Other branch instructions are explicit
        
        # Check for indirect jumps (MOV PC, reg, LDR PC, [PC, ...])
        if mnemonic in ["MOV", "LDR"]:
            num_operands = last_instr.getNumOperands()
            for i in range(num_operands):
                op_str = str(last_instr.getOpObjects(i)).upper()
                if "PC" in op_str:
                    return True  # Writing to PC is an explicit branch
        
        # Default: no explicit branch, falls through
        return False
        
    except Exception as e:
        # On error, assume fall-through
        return False

# --- Script Logic Starts Here ---

try:
    program = currentProgram
    
    if program is None:
        print("ERROR: No program loaded")
        sys.exit(1)
    
    print("INFO: Extracting minimal CFG from program: {}".format(program.getName()))
    print("INFO: Only extracting basic blocks and explicit/direct predecessors")
    
    # Create basic block model
    block_model = BasicBlockModel(program)
    
    # Dictionary to store CFG: normalized_block_address -> [[pred_addr, attribute], ...]
    cfg = {}
    # Dictionary to store block metadata: normalized_block_address -> {"end_pc": ..., "has_explicit_branch": ...}
    block_metadata = {}
    
    # Get all functions
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    processed_blocks = set()
    
    # Process each function
    function_count = 0
    monitor = getMonitor()
    
    for function in functions:
        if monitor.isCancelled():
            break
        
        function_count += 1
        function_body = function.getBody()
        
        # Get all basic blocks in this function
        blocks = block_model.getCodeBlocksContaining(function_body, monitor)
        
        while blocks.hasNext():
            block = blocks.next()
            block_start = block.getMinAddress()
            block_end = block.getMaxAddress()  
            block_addr = normalize_addr(block_start)  # Normalize address
            block_addr_str = "0x{:x}".format(block_addr)
            
            # Skip if already processed
            if block_addr_str in processed_blocks:
                continue
            processed_blocks.add(block_addr_str)
            
            block_end_normalized = normalize_addr(block_end)
            has_explicit_branch = check_has_explicit_branch(block, program)
            block_metadata[block_addr_str] = {
                "end_pc": block_end_normalized,
                "has_explicit_branch": has_explicit_branch
            }
            
            # Get predecessor blocks with attributes
            # Format: [[pred_addr, attribute], ...]
            predecessors = []
            pred_iter = block.getSources(monitor)
            while pred_iter.hasNext():
                pred_ref = pred_iter.next()
                pred_block = pred_ref.getSourceBlock()
                if pred_block:
                    pred_addr = normalize_addr(pred_block.getMinAddress())
                    pred_addr_str = "0x{:x}".format(pred_addr)
                    
                    # Determine edge attribute by analyzing the predecessor block
                    edge_attr = get_edge_attribute(pred_block, program)
                    
                    # Check if this predecessor is already in the list
                    pred_entry = [pred_addr_str, edge_attr]
                    if pred_entry not in predecessors:
                        predecessors.append(pred_entry)
            
            # Store in CFG (all addresses normalized, with attributes)
            # Sort by address for consistency
            predecessors.sort(key=lambda x: x[0])
            cfg[block_addr_str] = predecessors
        
        if function_count % 500 == 0:
            print("INFO: Processed {} functions...".format(function_count))
    
    print("INFO: Processed {} functions, found {} basic blocks".format(function_count, len(cfg)))
    
    # Get output path from environment variable
    output_path_env = os.environ.get("CFG_OUTPUT_PATH", "")
    if not output_path_env:
        print("WARNING: CFG_OUTPUT_PATH environment variable not set")
        output_path_env = "cfg_fallback.json"
        print("WARNING: Defaulting to {}".format(output_path_env))
    
    output_path = os.path.abspath(output_path_env)
    
    # Ensure directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print("INFO: Created output directory: {}".format(output_dir))
        except OSError:
            pass
    
    # Write JSON output (extended format: CFG + block metadata)
    print("INFO: Writing CFG data to: {}".format(output_path))
    
    output_data = {
        "cfg": cfg,
        "block_metadata": block_metadata  
    }
    
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=4, sort_keys=True)
    
    print("SUCCESS: Extracted {} basic blocks (all addresses normalized)".format(len(cfg)))
    print("SUCCESS: CFG data written to: {}".format(output_path))

except Exception as e:
    print("ERROR in CFG extraction script: {}".format(str(e)))
    import traceback
    traceback.print_exc()
    sys.exit(1)
