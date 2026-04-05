---
phase: 4
plan: 1
wave: 1
---

# Plan 4.1: Role Teammate Stub Handover

## Objective
Establish perfectly documented architecture stubs indicating exactly where Roles 2, 3, and 5 should hook into Role 1's `TaskStructIterator`. Prevent any unauthorized implementation of Process or Network extraction logic by Role 1.

## Context
- TEAM_ROLES.md

## Tasks

<task type="auto">
  <name>Generate Role 2 Process Stub</name>
  <files>core/parsers/processes.py</files>
  <action>
    - Create the file `core/parsers/processes.py`.
    - Write a massive top-level docstring explicitly addressing the "Process & Library Analyst (Role 2)".
    - Provide a purely empty stub `def extract_process_info(mapped_memory, struct_addr):` yielding `pass`.
    - Inject comments inside the block outlining exactly how Role 2 can use `struct.unpack("<I")` combining `struct_addr + config.OFFSET_PID` to satisfy their role. Do NOT write the unpack logic.
  </action>
  <verify>python -c "import core.parsers.processes"</verify>
  <done>File exists and imports cleanly with instructional comments only.</done>
</task>

<task type="auto">
  <name>Generate Role 3 Network Stub</name>
  <files>core/parsers/network.py</files>
  <action>
    - Create the file `core/parsers/network.py`.
    - Write a top-level docstring addressing the "Network Forensics Analyst (Role 3)".
    - Provide an empty stub `def extract_network_connections(mapped_memory, struct_addr):`.
    - Add `# TODO` comments explaining how socket arrays extend from `task_struct` pointers. Do NOT write extraction logic.
  </action>
  <verify>python -c "import core.parsers.network"</verify>
  <done>File exists and imports cleanly.</done>
</task>

<task type="auto">
  <name>Generate Role 5 Bridge Stub</name>
  <files>run_bridge.py</files>
  <action>
    - Create the root level `run_bridge.py`.
    - Write the `main()` python loop that instantiates `MemoryIngestor` and calls `TaskStructIterator.walk_tasks()`.
    - Within the loop, write `# TODO: ROLE 5` indicating where they should call Process/Network parsers and append the resulting dictionaries to the `raw_processes` list.
    - Write a `# TODO: GUI HANDOFF` explicitly showing an import to `integration.prepare_data_for_gui`. Do NOT write the full data passing arrays.
  </action>
  <verify>python -c "import run_bridge"</verify>
  <done>Runner loop is stubbed and guides downstream roles.</done>
</task>

## Success Criteria
- [ ] No Role 2 or Role 3 structural mapping logic is authored by Role 1.
- [ ] Stubs perfectly establish the layout required by downstream dependencies.
