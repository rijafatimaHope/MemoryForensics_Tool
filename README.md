# Memory Forensics Tool

A modular, pure Python forensics tool for analyzing Kali Linux memory dumps. This tool extracts running processes, network connections, and loaded libraries through direct data structure parsers, bypassing the need for heavy external frameworks. 

## Project Architecture & Directory Structure

The project is structured to allow massive collaborative development across frontend and backend teams natively.

```text
MemoryForensics_Tool/
├── config/
│   └── config.py            (Global constants, magic bytes, and thresholds)
├── core/
│   ├── ingestion.py         (Secure mmap loading to prevent Out Of Memory crashes)
│   └── scanner.py           (Linear signature scanning using Boyer-Moore searches)
├── tests/
│   ├── test_ingestion.py    (Bounds checking and file existence tests)
│   └── test_scanner.py      (Validation for kernel signature extraction)
├── dummy_data.py            (Pre-configured output samples for GUI Team development)
├── integration.py           (Bridge converting raw backend results into GUI formats)
├── search_filter.py         (Advanced sub-string search for the Process/Network tables)
└── test_backend_data.py     (Runner to validate backend outputs against Integration)
```

## How It Works

The engine operates via a strictly decoupled pipeline:
1. **Ingestion:** Maps large binary dumps using bounded `mmap.mmap()` to avoid high RAM consumption.
2. **Scanning:** Systematically searches for kernel profiles and Task Struct offset pointers.
3. **Extraction:** Navigates doubly linked lists to uncover processes and socket arrays.
4. **Integration:** Cleans, truncates, and enforces typing before passing the final data structures upstream to the Visualization layer.

## Setup Instructions
1. Clone the repository to your local machine.
2. Setup a standard Python virtual environment (`python -m venv venv`).
3. Place `.raw` or `.dd` memory dump files in the root execution environment.
4. Refer to `CONTRIBUTING.md` to see which components belong to your specific Role designation.
