---
phase: sec
plan: 1
wave: 1
---

# Plan sec.1: Security Remediation

## Objective
Patch the Path Traversal and JSON Schema Injection vulnerabilities discovered during the Phase 1/2 codebase audit.

## Context
- .gsd/phases/2/RESEARCH_SECURITY.md
- core/ingestion.py
- integration.py

## Tasks

<task type="auto">
  <name>Patch Core Ingestion Path Traversal</name>
  <files>core/ingestion.py</files>
  <action>
    - Import `os` (already present).
    - In `MemoryIngestor.__init__`, resolve the incoming path: `self.file_path = os.path.abspath(file_path)`.
    - Check if the resolved file ends with one of `('.raw', '.dd', '.vmem', '.img')`.
    - Raise `ValueError("Invalid memory dump extension.")` if it doesn't match.
  </action>
  <verify>python -c "from core.ingestion import MemoryIngestor; MemoryIngestor('bad_path.txt')"</verify>
  <done>ValueError is successfully raised before file logic executes.</done>
</task>

<task type="auto">
  <name>Patch Integration Schema Enforcement</name>
  <files>integration.py</files>
  <action>
    - Refactor `prepare_data_for_gui` block covering `cleaned_processes` and `cleaned_connections`.
    - Enforce stringent type mapping. E.g., `str(p.get('pid', 'N/A'))[:20]` to prevent memory DoS via unbounded strings.
    - Explicitly drop completely unexpected keys (this is already handled indirectly, but ensure we heavily truncate or enforce length limits on incoming json).
  </action>
  <verify>python test_backend_data.py</verify>
  <done>GUI Integration mapping continues to work cleanly under strict types.</done>
</task>

## Success Criteria
- [ ] Any attempt to initialize ingestion via relative path traversal or invalid executable files fails securely.
- [ ] Integration dictionary correctly trims and guards the types passed to the frontend framework.
