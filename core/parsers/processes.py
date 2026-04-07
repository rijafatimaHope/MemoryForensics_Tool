import struct
import logging
from config.config import OFFSET_PID, OFFSET_COMM, OFFSET_REAL_PARENT, OFFSET_START_TIME, OFFSET_TASKS

logger = logging.getLogger(__name__)

# core/parsers/processes.py

def extract_process_info(mapped_memory, struct_addr):
    try:
        # --- 1. Extract the PID ---
        mapped_memory.seek(struct_addr + OFFSET_PID)
        pid = struct.unpack("<i", mapped_memory.read(4))[0]

        # --- 2. Extract the Process Name (comm) ---
        mapped_memory.seek(struct_addr + OFFSET_COMM)
        name = mapped_memory.read(16).split(b'\x00')[0].decode('ascii', errors='ignore')

        # --- 3. Skip PPID ---
        ppid = "N/A"

        # --- 4. Extract the Time (start_time) ---
        mapped_memory.seek(struct_addr + OFFSET_START_TIME)
        start_time_ns = struct.unpack("<Q", mapped_memory.read(8))[0]
        time_str = f"{start_time_ns / 1_000_000_000:.2f} sec"

        return {
            'pid': pid,
            'name': name,
            'ppid': ppid, # Keeping the key but with "N/A" to avoid breaking the GUI
            'time': time_str
        }

    except Exception as e:
        logger.error(f"Failed to parse process info at {hex(struct_addr)}: {e}")
        return None