---
phase: 2.5
level: 1
---

# Security Remediation Research

## Questions Investigated
1. How to prevent Directory Traversal in `MemoryIngestor` without hardcoding a specific OS file path?
2. How to implement strong schema validation for `integration.py` without requiring heavy external dependencies (like `pydantic`) to maintain the "standard library only" constraint?

## Findings

### Path Traversal Prevention
Validating that the user input actually targets an expected memory dump file instead of a system shadow file requires extension white-listing and path stabilization (`os.path.abspath`).

**Recommendation:**
In `core/ingestion.py`, we will enforce:
1. Extension checking: `if not file_path.endswith(('.raw', '.dd', '.vmem', '.img'))`
2. We can also resolve the path with `os.path.abspath()` to ensure no weird `../` traversal tricks are passed down to lower-level C code bindings.

### JSON/Dictionary Schema Injection
Role 5's parsing currently trusts any structure given to `prepare_data_for_gui()`. Malformed dictionaries could cause missing keys, or overly massive dicts could trigger Out of Memory issues.
Since the project specification mandates minimal external libraries (No `pydantic`), we should use Python's built-in `dataclasses` or `typing.TypedDict` (Python 3.8+) mixed with explicit key validation in `integration.py`.

**Recommendation:**
Refactor `prepare_data_for_gui` to strictly cast and validate the keys. If an unknown key is provided, it is dropped. If types are egregiously wrong, they are cast to strings.

## Decisions Made
| Decision | Choice | Rationale |
|----------|--------|-----------|
| Path Verification | Extension Whitelisting | Simplest and highly effective guard against arbitrary read. |
| Schema Validation | Explicit Key Filtering | Avoids strict Pydantic requirements while ensuring GUI doesn't crash on garbage data. |

## Ready for Planning
- [x] Questions answered
- [x] Approach selected
- [x] Dependencies identified (None, pure Python)
