---
phase: 4
plan: 1
wave: 1
---

# Plan 4.1: Role 2 Extraction & GUI Pipeline Hook

## Objective
Finalize the Core Engine backend logic by mapping the discovered `task_struct` physical addresses to string-castable variables. Provide a top-level runner that ties the engine to the existing GUI data sanitizer (`integration.py`).

## Context
- .gsd/ROADMAP.md
- TEAM_ROLES.md

## Tasks

<task type="auto">
  <name>Build Process Structural Mapper (Role 2 Bridge)</name>
  <files>core/parsers/processes.py</files>
  <action>
    - Write a module parsing integers and strings from the physical buffer endpoints.
    - Implement `extract_process_info(mapped_memory, struct_addr)`.
    - Apply constraints: Bound `mapped_memory.seek(struct_addr + OFFSET_PID)` using `config.OFFSET_PID`.
    - Extract PID with `struct.unpack("<i", bytes)[0]`.
    - Bound `mapped_memory.seek(struct_addr + OFFSET_COMM)` using `config.OFFSET_COMM`.
    - Extract COMM exactly 16 bytes: `struct.unpack("16s", bytes)[0]`. Split it by `b'\x00'` to cull junk, and `.decode('utf-8')`.
    - Build exact python dictionary requested by GUI: `{'pid': pid, 'name': comm_str, 'ppid': 'N/A', 'time': 'N/A'}`.
  </action>
  <verify>python -c "from core.parsers.processes import extract_process_info"</verify>
  <done>Strings cleanly convert and map to standard dictionary payloads.</done>
</task>

<task type="auto">
  <name>Construct Root Level GUI Pipeline runner</name>
  <files>run_bridge.py</files>
  <action>
    - Establish `main()` block combining `MemoryIngestor` + `TaskStructIterator` + `extract_process_info`.
    - Push the array of processed struct dictionaries directly into `prepare_data_for_gui(raw_processes=[], raw_connections=[])` imported from `integration.py`.
    - Output `json.dumps()` or clean `print` structures to the console proving the GUI received cleanly filtered strings and bounds rather than core panics.
  </action>
  <verify>python -c "import run_bridge"</verify>
  <done>Whole-program flow securely integrates memory IO, struct decoding, and schema bounding simultaneously.</done>
</task>

## Success Criteria
- [ ] End-to-end extraction from a chunked `.raw` buffer yields human-readable text structs into `integration.py`.
- [ ] Core pipeline does not crash on malformed memory.
