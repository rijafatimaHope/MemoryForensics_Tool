import struct
import logging
from config.config import OFFSET_PID, OFFSET_COMM, OFFSET_REAL_PARENT, OFFSET_START_TIME

logger = logging.getLogger(__name__)

def extract_process_info(mapped_memory, struct_addr):
    """
    Extracts the PID, Name, PPID, and Creation Time from a task_struct.
    """
    try:
        # --- 1. Extract the PID ---
        mapped_memory.seek(struct_addr + OFFSET_PID)
        pid = struct.unpack("<i", mapped_memory.read(4))[0]

        # --- 2. Extract the Process Name (comm) ---
        mapped_memory.seek(struct_addr + OFFSET_COMM)
        name = mapped_memory.read(16).split(b'\x00')[0].decode('ascii', errors='ignore')

        # --- 3. Extract the PPID (real_parent) ---
        # Read the 8-byte pointer to the parent's task_struct
        mapped_memory.seek(struct_addr + OFFSET_REAL_PARENT)
        parent_virt_addr = struct.unpack("<Q", mapped_memory.read(8))[0]
        
        # Manually translate the Virtual Address to Physical 
        # (Stripping the 0xffffffff80000000 base)
        parent_phys_addr = parent_virt_addr - 0xffffffff80000000
        
        ppid = "N/A"
        # Jump to the parent's physical address and read its PID
        if 0 < parent_phys_addr < mapped_memory.size():
            mapped_memory.seek(parent_phys_addr + OFFSET_PID)
            ppid = struct.unpack("<i", mapped_memory.read(4))[0]

        # --- 4. Extract the Time (start_time) ---
        # Read the 8-byte unsigned integer (nanoseconds)
        mapped_memory.seek(struct_addr + OFFSET_START_TIME)
        start_time_ns = struct.unpack("<Q", mapped_memory.read(8))[0]
        
        # Convert nanoseconds to a readable string (seconds since system boot)
        time_str = f"{start_time_ns / 1_000_000_000:.2f} sec"

        return {
            'pid': pid,
            'name': name,
            'ppid': ppid,
            'time': time_str
        }

    except Exception as e:
        logger.error(f"Failed to parse process info at {hex(struct_addr)}: {e}")
        return None