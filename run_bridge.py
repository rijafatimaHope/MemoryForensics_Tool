# run_bridge.py
import os
from integration import get_live_backend_data

def main():
    print("Starting Memory Forensics Engine (CLI Mode)...")
    memory_dump_file = "sample_memory.raw"
    
    if not os.path.exists(memory_dump_file):
        print(f"[-] Error: {memory_dump_file} not found.")
        return

    # Call the centralized integration logic
    results = get_live_backend_data(memory_dump_file)
    
    if results:
        print(f"\n[+] Successfully carved {results['stats']['total_processes']} processes")
        print(f"[+] Successfully carved {results['stats']['total_connections']} connections")
        
        print("\n=== EXTRACTED PROCESSES ===")
        for p in results['processes']:
            print(f"PID: {p['pid']} | Name: {p['name']} | Time: {p['time']}")
            
        print("\n=== EXTRACTED CONNECTIONS ===")
        for c in results['connections']:
            print(f"PID: {c['pid']} | {c['local_ip']}:{c['local_port']} -> {c['remote_ip']}:{c['remote_port']} ({c['protocol']})")
    else:
        print("[-] Failed to extract data from memory.")

if __name__ == "__main__":
    main()