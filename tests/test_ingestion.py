import os
import pytest
import mmap
from core.ingestion import MemoryIngestor

DUMMY_FILE_PATH = "dummy_10mb.raw"
FILE_SIZE = 10 * 1024 * 1024  # 10 MB

@pytest.fixture
def dummy_dump():
    # Setup: Create a 10MB dummy file
    with open(DUMMY_FILE_PATH, "wb") as f:
        f.write(b"\x00" * FILE_SIZE)
    
    yield DUMMY_FILE_PATH
    
    # Teardown: Remove the file
    if os.path.exists(DUMMY_FILE_PATH):
        os.remove(DUMMY_FILE_PATH)

def test_ingestor_handles_existing_file(dummy_dump):
    # Test that we can open and map the dummy file without issues
    with MemoryIngestor(dummy_dump) as mapped:
        # Check that it's an mmap object
        assert isinstance(mapped, mmap.mmap)
        # Check that the mapped size matches
        assert mapped.size() == FILE_SIZE
        # Check we can read a byte
        assert mapped.read(1) == b"\x00"

def test_ingestor_raises_error_for_missing_file():
    # Test that a missing file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        MemoryIngestor("non_existent_file.raw")

def test_ingestor_raises_error_for_empty_file(tmp_path):
    # Create a 0-byte file
    empty_file = tmp_path / "empty.raw"
    empty_file.write_bytes(b"")
    
    with pytest.raises(ValueError, match="Memory dump file is empty"):
        MemoryIngestor(str(empty_file))
