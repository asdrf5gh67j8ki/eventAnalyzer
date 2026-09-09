"""Package a tested Windows x64 build. Python standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def project_version():
    text = (ROOT / 'CMakeLists.txt').read_text(encoding='utf-8')
    match = re.search(r'project\(\s*eventAnalyzer\s+VERSION\s+(\d+\.\d+\.\d+)\b', text)
    if not match:
        raise ValueError('Cannot read the project version from CMakeLists.txt.')
    return match.group(1)


def require_x64(exe):
    with exe.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('The executable is not a Windows PE file.')
        stream.seek(struct.unpack_from('<I', header, 60)[0])
        pe = stream.read(6)
    if len(pe) != 6 or pe[:4] != b'PE\0\0':
        raise ValueError('The executable has an invalid PE header.')
    if struct.unpack_from('<H', pe, 4)[0] != 0x8664:
        raise ValueError('An x64 executable is required. Configure a fresh build with -A x64.')


def run(exe, *args):
    result = subprocess.run([str(exe), *map(str, args)], capture_output=True,
                            text=True, encoding='utf-8', timeout=30)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}):\n'
                           f'{result.stdout}{result.stderr}')
    return result.stdout.strip()


def smoke_test(exe, fixture, database):
    def command(*args):
        return json.loads(run(exe, '--db', database, '--json', *args))

    imported = command('import', fixture, '--strict')
    if imported['inserted'] != 4 or imported['duplicates'] != 0:
        raise RuntimeError('The packaged demo did not import four new events.')
    if command('scan')['alerts'] != 3:
        raise RuntimeError('The packaged demo did not produce three alerts.')
    before = command('alerts')
    explanation = command('explain', str(before['alerts'][0]['id']))
    if len(explanation['ancestry']) != 2 or not explanation['ancestry'][0]['sources']:
        raise RuntimeError('The demo explanation is missing ancestry or source evidence.')
    repeated = command('import', fixture, '--strict')
    command('scan')
    stats = command('stats')
    if (repeated['inserted'] != 0 or repeated['duplicates'] != 4
            or command('alerts') != before or stats['events'] != 4
            or stats['source_records'] != 4 or not stats['scan_current']):
        raise RuntimeError('Repeated import/scan changed the demo counts or alert identities.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    require_x64(exe)
    if os.name != 'nt':
        raise RuntimeError('Run packaging on Windows so the extracted executable can be tested.')
    version = project_version()
    if run(exe, '--version') != version:
        raise ValueError('Executable and CMake project versions differ; rebuild before packaging.')
    tag = os.environ.get('GITHUB_REF', '')
    if tag.startswith('refs/tags/') and tag != f'refs/tags/v{version}':
        raise ValueError('The Git tag does not match the project version.')
    commit = os.environ.get('GITHUB_SHA', 'unavailable (local build)')
    name = f'eventAnalyzer-v{version}-windows-x64.zip'
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='eventAnalyzer-package-') as temp:
        work = Path(temp)
        stage = work / 'stage'
        files = {
            'eventAnalyzer.exe': exe,
            'README.md': ROOT / 'docs/windows-quickstart.md',
            'examples/demo.xml': ROOT / 'examples/demo.xml',
            'LICENSES/pugixml.txt': ROOT / 'vendor/pugixml/LICENSE.md',
        }
        if (ROOT / 'LICENSE').is_file():
            files['LICENSE'] = ROOT / 'LICENSE'
        for relative, source in files.items():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        (stage / 'BUILD-INFO.txt').write_text(
            f'eventAnalyzer {version}\nPlatform: Windows x64\nSource commit: {commit}\n',
            encoding='utf-8')
        archive = work / name
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
            for path in sorted(stage.rglob('*')):
                if path.is_file():
                    package.write(path, path.relative_to(stage).as_posix())
        extracted = work / 'extracted'
        with zipfile.ZipFile(archive) as package:
            package.extractall(extracted)
        smoke_test(extracted / 'eventAnalyzer.exe', extracted / 'examples/demo.xml',
                   work / 'smoke.db')
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        shutil.copyfile(archive, args.output / name)
        (args.output / (name + '.sha256')).write_text(f'{checksum}  {name}\n', encoding='ascii')
    print(f'Package verified: Windows x64, version {version}, 4 events, 3 alerts, stable repeated import.')
    print(args.output / name)
    print(args.output / (name + '.sha256'))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'Packaging failed: {error}') from error
