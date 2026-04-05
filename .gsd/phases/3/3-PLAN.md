---
phase: 3
plan: 1
wave: 1
---

# Plan 3.1: Task Struct Foundation Builder

## Objective
Establish the foundational physical memory traversal loop within the Core Engine for `task_struct` arrays. This provides Role 2 with the raw byte boundaries required for string extraction.

## Context
- .gsd/ROADMAP.md
- TEAM_ROLES.md

## Tasks

<task type="auto">
  <name>Configure Struct Offsets</name>
  <files>config/config.py</files>
  <action>
    Add placeholder offsets for traversing the Linux kernel (64-bit bounds):
    - `INIT_TASK_OFFSET = 0xffffffff82600000`
    - `OFFSET_TASKS = 0x398`
    - `OFFSET_PID = 0x4d8`
    - `OFFSET_COMM = 0x6e8`
    - `POINTER_SIZE = 8`
  </action>
  <verify>python -c "from config.config import OFFSET_TASKS; print(OFFSET_TASKS)"</verify>
  <done>Offsets are successfully imported into python scope.</done>
</task>

<task type="auto">
  <name>Construct Memory Loop Iterator</name>
  <files>core/parsers/task_struct.py</files>
  <action>
    Create `TaskStructIterator` class.
    - Implement an `__init__` that takes a `mapped_memory` object and `init_task_offset`.
    - Create a `walk_tasks()` generator that yields raw struct addresses.
    - Use `struct.unpack("<Q", bytes)[0]` to read the `tasks.next` pointer at `(addr + OFFSET_TASKS)`.
    - Apply a cyclic mapping guard: Maintain a `visited = set()` and break the generator when the next pointer matches `init_task_offset` or points to an already `visited` address.
    - AVOID trying to extract text fields like Comm here. Strictly adhere to Role 1 bounds.
  </action>
  <verify>python -c "from core.parsers.task_struct import TaskStructIterator"</verify>
  <done>Engine logic safely caches iterations without infinite loops.</done>
</task>

<task type="auto">
  <name>Test Circular List Unpacking</name>
  <files>tests/test_task_struct.py</files>
  <action>
    Write a `pytest` module injecting a tiny chained doubly-linked byte-array into a dummy file.
    - Validate that `TaskStructIterator.walk_tasks()` correctly spins through the 2 nodes constructed and outputs exactly 2 pointer addresses.
    - Test failure/break on a broken pointer.
  </action>
  <verify>python -m pytest tests/test_task_struct.py</verify>
  <done>Pytest perfectly models memory boundaries and extracts pointers.</done>
</task>

## Success Criteria
- [ ] Task Iterator accurately unpacks `unsigned long long` mapping bytes.
- [ ] Circular dependency checks completely block tool crashing.
