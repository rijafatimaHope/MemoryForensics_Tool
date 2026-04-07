# integration.py
import os
import struct
from core.ingestion import MemoryIngestor
from core.parsers.processes import extract_process_info
from core.parsers.network import extract_network_connections
from search_filter import filter_processes, filter_connections
from config.config import OFFSET_COMM, OFFSET_PID

def get_live_backend_data(memory_dump_path="sample_memory.raw"):
    """
    Triggers the Core Engine to parse the actual .raw dump instead of dummy data.
    """
    if not os.path.exists(memory_dump_path):
        return None

    all_procs = []
    all_conns = []

    # Use Role 1 Ingestor to map the real file
    with MemoryIngestor(memory_dump_path) as mapped:
        # Common Linux processes to search for directly in physical memory
        target_processes = [
            b"systemd\x00", b"kthreadd\x00", b"bash\x00", 
            b"sshd\x00", b"cron\x00"
        ]
        
        for target in target_processes:
            search_offset = 0
            while True:
                comm_offset = mapped.find(target, search_offset)
                if comm_offset == -1:
                    break
                    
                potential_base = comm_offset - OFFSET_COMM
                
                if potential_base > 0:
                    try:
                        # Verify PID to ensure it's a valid task_struct
                        mapped.seek(potential_base + OFFSET_PID)
                        pid = struct.unpack("<i", mapped.read(4))[0]
                        
                        if 0 < pid < 32768:
                            # Role 2: Extract process details
                            proc_data = extract_process_info(mapped, potential_base)
                            
                            if proc_data and not any(p['pid'] == pid for p in all_procs):
                                all_procs.append(proc_data)
                                
                                # Role 3: Extract network connections for this process
                                net_data = extract_network_connections(mapped, potential_base)
                                for conn in net_data:
                                    conn['pid'] = pid  # Assign real PID to the connection
                                all_conns.extend(net_data)
                    except Exception:
                        pass
                        
                search_offset = comm_offset + 1

    return prepare_data_for_gui(all_procs, all_conns)

def prepare_data_for_gui(raw_processes, raw_connections):
    """
    Cleans raw backend data for GUI rendering.
    """
    cleaned_processes = []
    for p in raw_processes:
        clean_p = {
            'pid': str(p.get('pid', 'N/A')),
            'name': str(p.get('name', 'Unknown')),
            'ppid': str(p.get('ppid', 'N/A')),
            'time': str(p.get('time', 'N/A'))
        }
        cleaned_processes.append(clean_p)
    
    cleaned_connections = []
    for c in raw_connections:
        clean_c = {
            'pid': str(c.get('pid', 'N/A')),
            'local_ip': str(c.get('local_ip', 'N/A')),
            'local_port': str(c.get('local_port', 'N/A')),
            'remote_ip': str(c.get('remote_ip', 'N/A')),
            'remote_port': str(c.get('remote_port', 'N/A')),
            'protocol': str(c.get('protocol', 'N/A'))
        }
        cleaned_connections.append(clean_c)
    
    stats = {
        'total_processes': len(cleaned_processes),
        'total_connections': len(cleaned_connections),
        'suspicious_count': count_suspicious(cleaned_processes)
    }
    
    return {
        'processes': cleaned_processes,
        'connections': cleaned_connections,
        'stats': stats
    }

def count_suspicious(processes):
    suspicious_keywords = ['malware', 'virus', 'rootkit', 'hidden', 'unknown']
    count = 0
    for p in processes:
        name_lower = p.get('name', '').lower()
        if any(k in name_lower for k in suspicious_keywords):
            count += 1
    return count

def search_in_prepared_data(prepared_data, search_term):
    if not search_term:
        return prepared_data
    filtered_processes = filter_processes(prepared_data['processes'], search_term)
    filtered_connections = filter_connections(prepared_data['connections'], search_term)
    return {
        'processes': filtered_processes,
        'connections': filtered_connections,
        'stats': {
            'total_processes': len(filtered_processes),
            'total_connections': len(filtered_connections),
            'suspicious_count': count_suspicious(filtered_processes)
        }
    }