First release of eventAnalyzer, an offline Sysmon process investigation CLI.

### Download

Download `eventAnalyzer-v1.0.0-windows-x64.zip`, extract it, and follow the
included `README.md`. It includes a Windows x64 executable and a synthetic
example that produces four events and three alerts. The example needs no
Sysmon installation, Python, compiler, or administrator access.

### Features

- Import Sysmon Event ID 1 XML into SQLite with source record references.
- Resolve observed process ancestry using process GUIDs and host context.
- Detect Office launching PowerShell, Office launching script hosts, and
  PowerShell encoded-command arguments.
- Explain findings with matched fields, timestamps, process GUIDs, and evidence.
- Inspect events, raw evidence XML, process trees, and host timelines.
- Preserve alert identities across repeated imports and scans.
- Report missing or conflicting ancestry and stale scan results explicitly.

### Scope

Input is exported XML, not native `.evtx`. Findings identify suspicious behavior;
they do not establish malicious execution. The encoded-command rule is a lexical
heuristic and does not decode or execute payloads. This release analyzes process
creation; it does not collect live telemetry or perform automated response.

The adjacent `.sha256` file contains the Windows ZIP's SHA-256 checksum.
`BUILD-INFO.txt` records the source commit used for the GitHub build.
