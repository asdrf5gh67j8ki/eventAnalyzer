"""Portable, reproducible wall-clock benchmark. All input is synthetic."""
import argparse
import json
import platform
import subprocess
import tempfile
import time
from pathlib import Path


def run(executable, count):
    if not 1 <= count <= 200000:
        raise ValueError('count must be between 1 and 200000')
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / 'synthetic.xml'
        database = root / 'case.db'
        with source.open('w', encoding='utf-8') as stream:
            stream.write('<Events>\n')
            for n in range(1, count + 1):
                suspicious = n % 100 == 0
                image = 'powershell.exe' if suspicious else 'notepad.exe'
                stream.write(
                    '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/>'
                    f'<EventID>1</EventID><EventRecordID>{n}</EventRecordID><Computer>BENCH</Computer>'
                    '</System><EventData>'
                    f'<Data Name="ProcessGuid">{{00000000-0000-0000-0000-{n:012d}}}</Data>'
                    f'<Data Name="ProcessId">{n % 10000}</Data>'
                    '<Data Name="UtcTime">2026-09-09 12:00:00.000</Data>'
                    f'<Data Name="Image">C:\\Windows\\{image}</Data>'
                    f'<Data Name="ParentImage">{"WINWORD.EXE" if suspicious else "explorer.exe"}</Data>'
                    '</EventData></Event>\n')
            stream.write('</Events>\n')
        measurements = []
        for name, args in [('import', ['import', str(source)]), ('scan', ['scan']),
                           ('duplicate_import', ['import', str(source)]), ('repeat_scan', ['scan'])]:
            start = time.perf_counter()
            result = subprocess.run([executable, '--db', str(database), '--json', *args],
                                    text=True, encoding='utf-8', capture_output=True, check=True)
            elapsed = time.perf_counter() - start
            measurements.append({'operation': name, 'seconds': round(elapsed, 6),
                                 'records_per_second': round(count / elapsed),
                                 'result': json.loads(result.stdout)})
        assert measurements[0]['result']['inserted'] == count
        assert measurements[1]['result']['alerts'] == count // 100
        assert measurements[2]['result']['duplicates'] == count
        assert measurements[3]['result']['alerts'] == count // 100
        return {'platform': platform.platform(), 'records': count, 'synthetic': True,
                'input_bytes': source.stat().st_size, 'database_bytes': database.stat().st_size,
                'timing': 'single-run wall clock, fixture generation excluded; no performance guarantee',
                'measurements': measurements}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('executable')
    parser.add_argument('--records', type=int, default=50000)
    args = parser.parse_args()
    print(json.dumps(run(str(Path(args.executable).resolve()), args.records), indent=2))
