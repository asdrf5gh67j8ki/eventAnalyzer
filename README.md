# eventAnalyzer

A tool for analyzing Windows process activity and detecting suspicious behavior in exported Sysmon logs. eventAnalyzer is designed to reconstruct process ancestry, apply detection rules, and explain alerts using the records that produced them.

This tool is designed to handle incomplete and repeated telemetry. It prevents duplicate events from generating duplicate alerts, uses process GUIDs and host context to distinguish processes with reused PIDs, and marks missing ancestry as unresolved. Each alert identifies the rule conditions that matched and links to the supporting records, distinguishing suspicious behavior from confirmed malicious activity.

The initial input format is XML containing Windows Event records from the Sysmon provider. Native binary `.evtx` parsing is outside the first release.

Features:

- Import Sysmon process-creation events from exported XML.
- Normalize timestamps, host identifiers, process identifiers, image paths, and command lines.
- Store normalized events and source evidence in SQLite.
- Reconstruct process ancestry using process GUIDs within host context.
- Evaluate a small set of documented detection rules.
- Explain each alert with its matching fields, supporting events, and process ancestry.
- Inspect a process timeline from the available records.
- Handle repeated imports without duplicating events or equivalent alerts.

## Quick start

Download `eventAnalyzer-v1.0.0-windows-x64.zip` from this repository's **Releases**
page, extract the entire ZIP, and open PowerShell in the extracted folder.
The release contains the executable, dependencies, and an example recording;
no compiler, Python, Sysmon installation, or administrator access is needed for
this example. Run the commands in the same PowerShell session:

```powershell
.\eventAnalyzer.exe --version
$eaCase = Join-Path $env:TEMP ('eventAnalyzer-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $eaCase -ErrorAction Stop | Out-Null
$eaDb = Join-Path $eaCase 'events.db'

.\eventAnalyzer.exe --db $eaDb import .\examples\demo.xml --strict
.\eventAnalyzer.exe --db $eaDb scan
.\eventAnalyzer.exe --db $eaDb alerts
.\eventAnalyzer.exe --db $eaDb explain 1
```

The synthetic recording produces **4 events and 3 alerts**. It is only read;
none of its recorded commands are executed.

```text
1 [medium] Office application launched PowerShell | event=1
2 [low] PowerShell used an encoded command argument | event=1
3 [medium] Office application launched a script host | event=4
```

Each explanation includes matching fields, source record references, timestamps,
and process GUIDs so you can check the finding against the input. See the
[full demo transcript](docs/demo-output.txt) for an example.

Repeat the import and scan to check deduplication:

```powershell
.\eventAnalyzer.exe --db $eaDb import .\examples\demo.xml --strict
.\eventAnalyzer.exe --db $eaDb scan
.\eventAnalyzer.exe --db $eaDb stats
```

The second import reports **0 new events and 4 duplicates**. Totals stay at
**4 events, 4 source records, and 3 alerts**. Run `.\eventAnalyzer.exe --help`
for the complete command list, or `.\eventAnalyzer.exe rules` for detection
logic and likely false positives.

## Build from source

Dependencies are bundled in `vendor/`: keep that directory when building.
You need a C++20 compiler, CMake 3.24 or newer, and Python 3 for the CLI tests.
Python needs no additional packages. Visual Studio 2026 requires CMake 4.2 or
newer and the Desktop development with C++ workload.

For Visual Studio 2026 on Windows, run from the source root:

```powershell
cmake -S . -B build-release -G "Visual Studio 18 2026" -A x64 -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DBUILD_TESTING=ON -DEA_WARNINGS_AS_ERRORS=ON
cmake --build build-release --config Release --parallel
ctest --test-dir build-release -C Release --output-on-failure
```

For Visual Studio 2022, change the generator to `"Visual Studio 17 2022"`.
CTest should run both `core` and `cli`: together they contain 43 test cases.
Stop if either suite fails. Your executable is
`build-release\Release\eventAnalyzer.exe`; use that path in place of
`.\eventAnalyzer.exe` in the examples when running from the source root.

On Linux with GCC or Clang:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DEA_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/eventAnalyzer --help
```

The [release guide](docs/github-release.md) covers publishing the repository,
downloading the executable built by GitHub Actions, and creating a release.

## Architecture

Sysmon supplies the telemetry. eventAnalyzer supplies the import, correlation, detection, and investigation logic. Saved recordings allow analysis and testing without a live collection session.
<img width="900" height="1411" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/b919499a-ead3-43c9-8e69-276d7c8697ed" />


## Live Sysmon demo

This walkthrough runs a harmless PowerShell command, captures its process-creation event from Sysmon, and explains the resulting alert. The command only prints eventAnalyzer demo.

Prerequisites: Sysmon must already record Event ID 1 with command lines. Open
an elevated PowerShell session and run every step in that same session. From
the downloaded release folder use the executable path below; for a source build,
use `.\build-release\Release\eventAnalyzer.exe` instead.

### 1. Setup

Set the executable path and create a new temporary directory for this run. Adjust the first line if your executable is elsewhere.
```powershell
$eaExe = (Resolve-Path '.\eventAnalyzer.exe' -ErrorAction Stop).Path
$eaLog = 'Microsoft-Windows-Sysmon/Operational'
Get-WinEvent -ListLog $eaLog -ErrorAction Stop | Out-Null
```
```powershell
$eaDemo = Join-Path $env:TEMP ('eventAnalyzer-demo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $eaDemo -ErrorAction Stop | Out-Null
$eaXml = Join-Path $eaDemo 'process.xml'
$eaDb = Join-Path $eaDemo 'events.db'
```

### 2. Generate a harmless event

PowerShell `-EncodedCommand` accepts a Base64 representation of UTF-16LE text. Here that text is just a `Write-Output` command.
```powershell
$eaCommand = "Write-Output 'eventAnalyzer demo'"
$eaEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($eaCommand))
$eaStarted = Get-Date
```
```powershell
$eaProcess = Start-Process -FilePath powershell.exe `
    -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $eaEncoded" `
    -NoNewWindow -Wait -PassThru -ErrorAction Stop
```

The child process should print `eventAnalyzer demo`.

### 3. Capture that process's Sysmon record

This waits up to approximately 15 seconds for telemetry. It matches the PID, creation window, and encoded command so unrelated activity is excluded.
```powershell
$eaQuery = "*[System[EventID=1] and EventData[Data[@Name='ProcessId']='$($eaProcess.Id)']]"
$eaEvent = $null

for($eaAttempt = 0; $eaAttempt -lt 15; $eaAttempt++){
    $eaEvent = Get-WinEvent -LogName $eaLog -FilterXPath $eaQuery `
        -MaxEvents 1 -ErrorAction SilentlyContinue | Where-Object {
            $_.TimeCreated -ge $eaStarted -and $_.ToXml().Contains($eaEncoded)
        }
    if($eaEvent){ break }
    Start-Sleep -Seconds 1
}

if(-not $eaEvent){
    throw 'Demo event not found. Check that Sysmon records PowerShell process creation and command lines, then retry from step 2.'
}

$eaEvent.ToXml() | Set-Content -LiteralPath $eaXml -Encoding utf8 -ErrorAction Stop
```

The file now contains one Sysmon event. eventAnalyzer accepts a single Event element, so no XML wrapper is needed.

### 4. Import, detect, explain

```powershell
& $eaExe --db $eaDb import $eaXml --strict
if($LASTEXITCODE -ne 0){ throw 'Import failed; see the error above.' }

& $eaExe --db $eaDb scan
if($LASTEXITCODE -ne 0){ throw 'Scan failed; see the error above.' }

& $eaExe --db $eaDb alerts
& $eaExe --db $eaDb explain 1
```
The import should report 1 event, and the scan should report 1 alert:
```
Scan complete: 1 alerts.
1 [low] PowerShell used an encoded command argument | event=1
```

The explanation identifies `powershell_encoded_command` version 1 and shows the matched `Image`, `CommandLine`, and `-EncodedCommand`. It also includes the event's timestamp, process GUID, source file, and EventRecordID.

Why it triggered: the invocation used an encoded command argument. That is the suspicious behavior the rule detects; it does not establish that the payload is malicious. This demonstration's payload is harmless.

Only the child event was imported. An ancestry result of `parent_unobserved` is expected: eventAnalyzer retains the reported parent information without inventing an observed parent record.

You can see the dupe handling by importing the same recording and scanning again:
```powershell
& $eaExe --db $eaDb import $eaXml --strict
& $eaExe --db $eaDb scan
& $eaExe --db $eaDb stats
```
The second import should report 0 new events and 1 duplicate. Totals should remain 1 event, 1 source record, and 1 alert. The captured XML and database remain available in the directory shown by:
```powershell
$eaDemo
```
If the event is not found, check Sysmon's process-creation filters and the session's log-read permissions. If the analyzer reports no alert, inspect `event 1` and confirm that its command line contains `-EncodedCommand` followed by the encoded value.

## Scope

The first release focuses on offline process-creation analysis. Live collection, kernel drivers, automated response, network-event analysis, and a graphical interface are outside its scope.

## References

[Microsoft Sysmon docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) describe the telemetry, configuration, and event fields.
