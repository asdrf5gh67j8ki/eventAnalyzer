# Release verification — 1.0.0

Executed on Linux x86-64 with GCC 13.3.0, CMake 4.4.3 and Python 3.12.
The release uses bundled pugixml 1.16 and SQLite 3.53.4.

## Results

| Check | Result |
| --- | --- |
| Release build with warnings treated as errors | Passed |
| 26 C++ core test cases | Passed |
| 17 Python CLI integration test cases | Passed |
| Debug build with AddressSanitizer and UndefinedBehaviorSanitizer | Passed |
| The same 43 cases under address/undefined sanitizers | Passed; leak detection disabled |
| Synthetic demo: 4 events, 3 alerts | Passed |
| Repeated demo import and scan | Counts and alert IDs preserved |
| 50,000-record benchmark with expected 500 alerts | Passed; rerun `tools/benchmark.py` for measurements on your machine |
| Bundled SQLite archive checksum | Matches published SHA3-256 |
| Windows x86/MSVC 19.51 Release build | Passed on the maintainer's machine; supplied build and test logs |
| Windows x86: 26 core + 17 CLI cases | Passed in the supplied `LastTest.log` |
| Windows x64 release package | Run the included GitHub Actions workflow to verify |
| Real endpoint telemetry validation | Not executed; included test data is synthetic |

LeakSanitizer cannot operate in this traced execution environment. The first
sanitizer attempt reported that limitation. Subsequent runs used
`ASAN_OPTIONS=detect_leaks=0`; address and undefined-behavior instrumentation
remained enabled. No leak-clean claim is made. The CI workflow leaves normal
sanitizer defaults in place for a supported runner.

## Covered behavior

- GUID case/braces, strict numeric parsing, UTC precision and calendar validity.
- Windows image basenames on Linux, source text escaping, and optional fields.
- Malformed documents, prohibited DTDs, duplicate data fields, missing required
  fields, invalid XML characters, field-size limits and unsupported event types.
- Default and prefixed XML namespaces, UTF-16 recordings, Unicode filenames,
  inherited namespace preservation in exported evidence, and UTF-8 command lines.
- Duplicate imports, alternate source paths, differing EventRecordIDs,
  SQL parameter binding and conflicting process identities.
- PID reuse, host isolation, missing parents, children imported before parents,
  temporal contradictions, parent metadata conflicts, cycles and depth bounds.
- Rule matches and nonmatches, exact image-name boundaries, reported-parent
  evidence, and encoded-command heuristic limits.
- Alert ID stability, scan freshness, timeline queries, source retrieval,
  missing IDs and invalid arguments.
- Strict rejection without creating or modifying a database, malformed-document
  rejection before writes, unrelated schema preservation and schema-version checks.
- Full transaction rollback when a new event would exceed the 250,000-event case
  limit. The boundary test fills the database using SQL rather than committing a
  large generated fixture to the repository.

CTest reports two suites (`core` and `cli`); those suites contain 43 individual
cases. Python is required to execute the CLI suite. The supplied Windows test
log covers x86; the new x64 packaging workflow has not been executed in this
preparation environment. Its first successful GitHub run is the release gate.

## Reproduction

Use the build/test commands in the main README. The benchmark script generates
its own temporary recording and database, verifies expected counts, then removes
both. Fixture generation is excluded from its timings. The numbers describe a
single synthetic workload on this host, not real-world EDR detection coverage,
production scale, or guaranteed performance.

The demo transcript is in `demo-output.txt`. Absolute fixture paths in that
transcript are replaced with `PROJECT` to keep the output portable.
