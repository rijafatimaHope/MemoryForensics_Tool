import os
import struct
from core.ingestion import MemoryIngestor
from core.parsers.processes import extract_process_info
from config.config import OFFSET_COMM, OFFSET_PID

def main():
    print("Starting Memory Forensics Engine...")
    memory_dump_file = "sample_memory.raw"
    
    if not os.path.exists(memory_dump_file):
        print(f"Waiting for {memory_dump_file} to be added...")
        return

    with MemoryIngestor(memory_dump_file) as mapped:
        print("Memory successfully inside the engine!")
        print("Role 1 Page Tables missing. Initiating Signature-Based Memory Scanner (psscan)...")
        
        # Common Linux processes to search for directly in physical memory
        target_processes = [
            b"systemd\x00", b"kthreadd\x00", b"kworker", 
            b"rcu_gp\x00", b"bash\x00", b"sshd\x00", b"cron\x00"
        ]
        
        print("\n=== EXTRACTED PROCESSES ===") #ROLE 2 PARSER OUTPUT
        valid_processes = []
        
        for target in target_processes:
            search_offset = 0
            while len(valid_processes) < 10:
                comm_offset = mapped.find(target, search_offset)
                if comm_offset == -1:
                    break
                    
                potential_base = comm_offset - OFFSET_COMM
                
                # If we found a string, let's mathematically verify it is a real task_struct
                if potential_base > 0:
                    try:
                        mapped.seek(potential_base + OFFSET_PID)
                        pid = struct.unpack("<i", mapped.read(4))[0]
                        
                        # Valid Linux PIDs are between 1 and 32768
                        if 0 < pid < 32768:
                            # CALLING ROLE 2 PARSER!
                            process_data = extract_process_info(mapped, potential_base)
                            
                            # Print it if it is valid and not a duplicate
                            if process_data and process_data['pid'] == pid:
                                if not any(p['pid'] == pid for p in valid_processes):
                                    print(process_data)
                                    valid_processes.append(process_data)
                    except Exception:
                        pass
                        
                search_offset = comm_offset + 1
                
        print(f"\n[+] Successfully carved {len(valid_processes)} processes directly from physical RAM!")

if __name__ == "__main__":
    main()
