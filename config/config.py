# config.py
# Constants and configurations for MemoryForensics Tool

# The maximum percentage of system RAM we are allowed to use when chunking
MEMORY_LIMIT_PCT = 0.40

# Logging verbosity
LOG_LEVEL = "INFO"

# Default chunk sizes for reading (in bytes) if we fall back from mmap
DEFAULT_CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB chunks

# Kernel Signature Definitions
LINUX_BANNER_MAGIC = b"Linux version "
MAX_BANNER_LENGTH = 128


# Task Struct Engine Offsets 
INIT_TASK_OFFSET = 0x14c130c0
OFFSET_TASKS = 0x9c0
OFFSET_PID = 0xa90
OFFSET_COMM = 0xcb0
POINTER_SIZE = 8

OFFSET_REAL_PARENT = 0xaa0
OFFSET_START_TIME = 0xbe8

OFFSET_FILES = 0xcf8
OFFSET_FDT = 0x20
OFFSET_FD_ARRAY = 0x8
OFFSET_FILE_PRIVATE = 0x18
OFFSET_SOCK_SK = 0x18
OFFSET_INET_SPORT = 0x32e
OFFSET_INET_DPORT = 0xc
OFFSET_INET_SADDR = 0x328
OFFSET_INET_DADDR = 0x0
