import os
import pytest
from core.ingestion import MemoryIngestor
from core.scanner import KernelScanner, SignatureNotFoundError

DUMMY_SCAN_FILE = "dummy_scan.raw"
FILE_SIZE = 5 * 1024 * 1024  # 5 MB

@pytest.fixture
def dummy_dump_with_banner():
    # Setup: Create a 5MB dummy file with the banner embedded in the middle
    with open(DUMMY_SCAN_FILE, "wb") as f:
        f.write(b"\x00" * (FILE_SIZE // 2))
        f.write(b"Linux version 5.15.0-kali3-amd64 (devel@kali.org)\n")
        f.write(b"\x00" * ((FILE_SIZE // 2) - 50))
    
    yield DUMMY_SCAN_FILE
    
    # Teardown
    if os.path.exists(DUMMY_SCAN_FILE):
        os.remove(DUMMY_SCAN_FILE)

@pytest.fixture
def dummy_dump_without_banner():
    # Setup: Create a dummy file without the banner
    NO_BANNER_FILE = "dummy_no_banner.raw"
    with open(NO_BANNER_FILE, "wb") as f:
        f.write(b"\xff" * FILE_SIZE)
        
    yield NO_BANNER_FILE
    
    if os.path.exists(NO_BANNER_FILE):
        os.remove(NO_BANNER_FILE)

def test_find_linux_banner_success(dummy_dump_with_banner):
    with MemoryIngestor(dummy_dump_with_banner) as mapped:
        scanner = KernelScanner(mapped)
        banner = scanner.find_linux_banner()
        assert banner == "Linux version 5.15.0-kali3-amd64 (devel@kali.org)"

def test_find_linux_banner_failure(dummy_dump_without_banner):
    with MemoryIngestor(dummy_dump_without_banner) as mapped:
        scanner = KernelScanner(mapped)
        with pytest.raises(SignatureNotFoundError):
            scanner.find_linux_banner()
