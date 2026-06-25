import os
import sys
import json
import struct
from elftools.elf.elffile import ELFFile


def extract_vector_table_from_elf(elf_path):
    """
    从 .isr_vector 或 .vectors section 读取向量表。
    """
    isr_set = set()

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        vector_sec = elf.get_section_by_name('.isr_vector')
        if not vector_sec:
            vector_sec = elf.get_section_by_name('.vectors')

        if not vector_sec:
            print(f"    -> [Error] No .isr_vector or .vectors section found in ELF")
            return isr_set

        print(f"    -> Found vector section: {vector_sec.name}")
        data = vector_sec.data()
        
        count = len(data) // 4
        print(f"    -> Parsing {count} entries based on section size")
        
        for i in range(count):
            if i == 0:
                continue
            
            word = struct.unpack_from("<I", data, i * 4)[0]
            
            if word & 1 == 0:
                continue

            pc = word & ~1
            
            if pc > 0: 
                isr_set.add(pc)
    
    return isr_set


def main():
    firmware_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    output_path = os.path.join(firmware_dir, "isr_whitelist.json")

    elf_path = None
    
    if os.path.isdir(firmware_dir):
        elf_files = []
        for entry in os.listdir(firmware_dir):
            if entry.endswith(".elf"):
                full_path = os.path.join(firmware_dir, entry)
                if os.path.isfile(full_path):
                    elf_files.append(full_path)
        
        if elf_files:
            dir_name = os.path.basename(firmware_dir)
            matching = [f for f in elf_files if os.path.basename(f).startswith(dir_name)]
            if matching:
                elf_path = matching[0]
            else:
                elf_path = elf_files[0]

    if not elf_path:
        print("[!] ELF not found in directory: {}".format(firmware_dir))
        sys.exit(1)

    print(f"[-] Parsing vector table from ELF: {elf_path}")
    vector_isrs = extract_vector_table_from_elf(elf_path)

    print(f"[+] Vector table ISR entries: {len(vector_isrs)}")

    output = {
        "valid_isr_set": [hex(x) for x in sorted(vector_isrs)]
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Written to {output_path}")


if __name__ == "__main__":
    main()
