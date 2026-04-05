# ==========================================
# NETWORK FORENSICS ANALYST (Role 3) - Muhammad Abdullah
# ==========================================
import struct
import socket

from config.config import (
    POINTER_SIZE, OFFSET_FILES, OFFSET_FDT, OFFSET_FD_ARRAY,
    OFFSET_FILE_PRIVATE, OFFSET_SOCK_SK, OFFSET_INET_SPORT,
    OFFSET_INET_DPORT, OFFSET_INET_SADDR, OFFSET_INET_DADDR
)

def extract_network_connections(mapped_memory, struct_addr, pid=0, process_name="unknown"):
    connections = []

    def v2p(virt_addr):
        """Translates a kernel virtual address to a physical offset."""
        if virt_addr == 0:
            return 0
        return virt_addr - 0xffffffff80000000

    def read_qword(phys_addr):
        # Size boundaries check to avoid raw dump out-of-bounds
        if phys_addr < 0 or phys_addr >= mapped_memory.size():
            return 0
        mapped_memory.seek(phys_addr)
        
        # CRITICAL: Extract the integer from the tuple
        return struct.unpack("<Q", mapped_memory.read(POINTER_SIZE))[0]

    def read_word(phys_addr):
        if phys_addr < 0 or phys_addr >= mapped_memory.size():
            return 0
        mapped_memory.seek(phys_addr)
        
        # CRITICAL: Extract the integer from the tuple
        return struct.unpack(">H", mapped_memory.read(2))[0]

    try:
        # 1. task_struct -> files_struct
        files_struct_virt = read_qword(struct_addr + OFFSET_FILES)
        if files_struct_virt == 0:
            print(f"  [DEBUG PID {pid}] No files_struct found at offset {hex(OFFSET_FILES)}")
            return connections
            
        files_struct_phys = v2p(files_struct_virt)

        # 2. files_struct -> fdtable
        fdt_virt = read_qword(files_struct_phys + OFFSET_FDT)
        fdt_phys = v2p(fdt_virt)

        # 3. fdtable -> fd_array
        fd_array_virt = read_qword(fdt_phys + OFFSET_FD_ARRAY)
        fd_array_phys = v2p(fd_array_virt)

        # 4. Check first 256 file descriptors
        found_fds = 0
        for i in range(256):
            file_virt = read_qword(fd_array_phys + (i * POINTER_SIZE))
            if file_virt == 0:
                continue
            found_fds += 1
            file_phys = v2p(file_virt)

            # 5. file -> private_data (socket)
            socket_virt = read_qword(file_phys + OFFSET_FILE_PRIVATE)
            if socket_virt == 0:
                continue
            socket_phys = v2p(socket_virt)

            # 6. socket -> sock
            sock_virt = read_qword(socket_phys + OFFSET_SOCK_SK)
            if sock_virt == 0:
                continue
            sock_phys = v2p(sock_virt)

            # 7. Extract IP and Ports
            if sock_phys + OFFSET_INET_DADDR + 4 > mapped_memory.size():
                continue

            mapped_memory.seek(sock_phys + OFFSET_INET_SADDR)
            saddr_bytes = mapped_memory.read(4)
            local_ip = socket.inet_ntoa(saddr_bytes)

            mapped_memory.seek(sock_phys + OFFSET_INET_DADDR)
            daddr_bytes = mapped_memory.read(4)
            remote_ip = socket.inet_ntoa(daddr_bytes)

            local_port = read_word(sock_phys + OFFSET_INET_SPORT)
            remote_port = read_word(sock_phys + OFFSET_INET_DPORT)

            protocol = "TCP"

            if local_ip != "0.0.0.0" or remote_ip != "0.0.0.0":
                connections.append({
                    "pid": pid,
                    "process_name": process_name,
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": "ESTABLISHED"
                })

        if found_fds > 0 and len(connections) == 0:
            print(f"  [DEBUG PID {pid}] Found {found_fds} file descriptors but none were network sockets")

    except Exception as e:
        print(f"DEBUG: Network parsing failed for PID {pid}: {e}")

    return connections