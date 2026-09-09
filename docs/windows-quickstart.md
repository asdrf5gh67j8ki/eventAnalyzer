# eventAnalyzer — Windows x64

Extract the entire ZIP and open PowerShell in the extracted folder.
Run commands in the same PowerShell session. The executable includes SQLite,
pugixml, and the MSVC runtime. Python, CMake, Visual Studio, and Sysmon are not
needed to analyze the included recording.

## Try the included example

The example is synthetic: reading it does not execute the recorded commands.
Create a fresh temporary database so every run starts with the same counts:

```powershell
.\eventAnalyzer.exe --version
.\eventAnalyzer.exe --help

$eaCase = Join-Path $env:TEMP ('eventAnalyzer-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $eaCase -ErrorAction Stop | Out-Null
$eaDb = Join-Path $eaCase 'events.db'

.\eventAnalyzer.exe --db $eaDb import .\examples\demo.xml --strict
.\eventAnalyzer.exe --db $eaDb scan
.\eventAnalyzer.exe --db $eaDb alerts
.\eventAnalyzer.exe --db $eaDb explain 1
```

Expected: **4 imported events and 3 alerts**. The explanation shows the matching
fields, timestamps, process GUIDs, observed ancestry, and source record references.

```text
1 [medium] Office application launched PowerShell | event=1
2 [low] PowerShell used an encoded command argument | event=1
3 [medium] Office application launched a script host | event=4
```

Repeat the import and scan:

```powershell
.\eventAnalyzer.exe --db $eaDb import .\examples\demo.xml --strict
.\eventAnalyzer.exe --db $eaDb scan
.\eventAnalyzer.exe --db $eaDb stats
```

Expected: **0 new events, 4 duplicates**, with totals of **4 events, 4 source
records, and 3 alerts**. Your database remains at the path printed by `$eaDb`.

## Analyze your own recording

Use a separate database for each investigation:

```powershell
.\eventAnalyzer.exe --db investigation.db import .\events.xml --strict
.\eventAnalyzer.exe --db investigation.db scan
.\eventAnalyzer.exe --db investigation.db alerts
```

Input must be XML containing Sysmon Event ID 1 records. Native `.evtx` files
are not supported. `--strict` rejects the entire import if any record is invalid.
Use `explain ALERT_ID`, `event EVENT_ID --raw`, and `tree EVENT_ID` to inspect
findings. An alert identifies suspicious behavior, not confirmed malicious activity.

`BUILD-INFO.txt` identifies the version and source commit of a GitHub build.
pugixml's license is included in `LICENSES/pugixml.txt`; SQLite is public domain.
