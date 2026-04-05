---
phase: 4
plan: 1
wave: 1
---

# Plan 4.1: Plain English Teammate Handoff

## Objective
Provide clean, empty python files for teammates to work in. Keep the instructions plain, friendly, and easy to understand containing zero technical jargon.

## Context
- TEAM_ROLES.md

## Tasks

<task type="auto">
  <name>Generate Role 2 Process Stub</name>
  <files>core/parsers/processes.py</files>
  <action>
    - Create `core/parsers/processes.py`.
    - Write a simple, friendly English comment explaining that Role 2 should use the memory address given by Role 1 to extract the Process Name and PID.
    - Write an empty `extract_process_info` function with `pass`.
  </action>
  <verify>python -c "import core.parsers.processes"</verify>
  <done>File exists containing simple plain english notes.</done>
</task>

<task type="auto">
  <name>Generate Role 3 Network Stub</name>
  <files>core/parsers/network.py</files>
  <action>
    - Create `core/parsers/network.py`.
    - Write a simple English comment explaining that Role 3 should extract IP addresses from the process.
    - Write an empty `extract_network_connections` function with `pass`.
  </action>
  <verify>python -c "import core.parsers.network"</verify>
  <done>File exists containing simple plain english notes.</done>
</task>

<task type="auto">
  <name>Generate Role 5 Bridge Stub</name>
  <files>run_bridge.py</files>
  <action>
    - Create `run_bridge.py`.
    - Set up `MemoryIngestor` and the `TaskStructIterator`.
    - Add a simple comment for Role 5: "Hey Role 5, call Role 2's process extractor here, then pass the dictionary list to integration.py".
  </action>
  <verify>python -c "import run_bridge"</verify>
  <done>Runner loop is stubbed with plain English.</done>
</task>

## Success Criteria
- [ ] No technical jargon or deep python internals mentioned.
- [ ] Strictly follows plain English formatting.
