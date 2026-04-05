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

