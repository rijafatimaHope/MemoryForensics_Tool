# ==========================================
# NETWORK FORENSICS ANALYST (Role 3)
# ==========================================
import struct
import socket
import logging
from config.config import (
    POINTER_SIZE, OFFSET_FILES, OFFSET_FDT, OFFSET_FD_ARRAY,
    OFFSET_FILE_PRIVATE, OFFSET_SOCK_SK, OFFSET_INET_SPORT,
    OFFSET_INET_DPORT, OFFSET_INET_SADDR, OFFSET_INET_DADDR
)

logger = logging.getLogger(__name__)

def extract_network_connections(mapped_memory, struct_addr):
    """
    Extracts network connections for ONE process by traversing the 
    task_struct -> files_struct -> fdtable -> fd_array -> socket path.
    """
    connections = []
    try:
        # 1. task_struct -> files_struct
        mapped_memory.seek(struct_addr + OFFSET_FILES)
        files_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
        
        if files_virt_ptr == 0 or files_virt_ptr == 0xffffffff80000000:
            return connections

        # Translate Virtual Address to Physical Offset
        files_struct_phys = files_virt_ptr & 0xFFFFFFFF
        
        if files_struct_phys >= mapped_memory.size():
            return connections

        # 2. files_struct -> fdtable (fdt)
        mapped_memory.seek(files_struct_phys + OFFSET_FDT)
        fdt_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
        fdt_phys = fdt_virt_ptr & 0xFFFFFFFF

        # 3. fdtable -> fd_array
        mapped_memory.seek(fdt_phys + OFFSET_FD_ARRAY)
        fd_array_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
        fd_array_phys = fd_array_virt_ptr & 0xFFFFFFFF

        # 4. Check file descriptors (Iterate through the first 64 for performance)
        for i in range(64):
            mapped_memory.seek(fd_array_phys + (i * POINTER_SIZE))
            file_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            
            if file_virt_ptr == 0:
                continue

            file_phys = file_virt_ptr & 0xFFFFFFFF
            if file_phys >= mapped_memory.size():
                continue

            # 5. file -> private_data (Points to a socket object if it's a network FD)
            mapped_memory.seek(file_phys + OFFSET_FILE_PRIVATE)
            socket_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            
            if socket_virt_ptr == 0:
                continue

            socket_phys = socket_virt_ptr & 0xFFFFFFFF
            if socket_phys >= mapped_memory.size():
                continue

            # 6. socket -> sock (sk)
            mapped_memory.seek(socket_phys + OFFSET_SOCK_SK)
            sock_virt_ptr = struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]
            
            if sock_virt_ptr == 0:
                continue

            sock_phys = sock_virt_ptr & 0xFFFFFFFF
            if sock_phys >= mapped_memory.size():
                continue

            # 7. Extract IP and Ports from the 'sock' structure
            # Local IP (Source)
            mapped_memory.seek(sock_phys + OFFSET_INET_SADDR)
            saddr_bytes = mapped_memory.read(4)
            local_ip = socket.inet_ntoa(saddr_bytes)

            # Remote IP (Destination)
            mapped_memory.seek(sock_phys + OFFSET_INET_DADDR)
            daddr_bytes = mapped_memory.read(4)
            remote_ip = socket.inet_ntoa(daddr_bytes)

            # Ports (Stored in Network Byte Order / Big-Endian)
            mapped_memory.seek(sock_phys + OFFSET_INET_SPORT)
            local_port = struct.unpack(">H", mapped_memory.read(2))[0]

            mapped_memory.seek(sock_phys + OFFSET_INET_DPORT)
            remote_port = struct.unpack(">H", mapped_memory.read(2))[0]

            # Filter out empty/invalid connections
            if local_ip != "0.0.0.0" or remote_ip != "0.0.0.0":
                connections.append({
                    "pid": 0,  # Linked by integration.py
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": "TCP" if local_port < 32768 else "UDP"
                })

    except Exception as e:
        # Silently fail for individual bad pointers to keep the scan moving
        pass

    return connections