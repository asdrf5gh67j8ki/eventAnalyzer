"""CLI integration tests. Standard library only; every fixture is synthetic."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from xml.etree import ElementTree as ET

EXE = str(Path(sys.argv.pop(1)).resolve())
NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def record(number, parent=None, image=r'C:\Windows\notepad.exe', parent_image=None,
           command=None, host='LAB', timestamp='2026-09-09 12:00:00.000'):
    event = ET.Element('Event')
    system = ET.SubElement(event, 'System')
    ET.SubElement(system, 'Provider', Name='Microsoft-Windows-Sysmon')
    ET.SubElement(system, 'EventID').text = '1'
    ET.SubElement(system, 'EventRecordID').text = str(number)
    ET.SubElement(system, 'Computer').text = host
    fields = {'ProcessGuid': f'{{00000000-0000-0000-0000-{number:012d}}}',
              'ProcessId': '100', 'Image': image, 'UtcTime': timestamp}
    if parent is not None:
        fields['ParentProcessGuid'] = f'{{00000000-0000-0000-0000-{parent:012d}}}'
        fields['ParentProcessId'] = '100'
    if parent_image is not None:
        fields['ParentImage'] = parent_image
    if command is not None:
        fields['CommandLine'] = command
    data = ET.SubElement(event, 'EventData')
    for name, value in fields.items():
        ET.SubElement(data, 'Data', Name=name).text = value
    return event


class CLITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / 'case.db'

    def tearDown(self):
        self.temp.cleanup()

    def call(self, *args, status=0, json_output=True, db=None):
        command = [EXE, '--db', str(db or self.db)]
        if json_output:
            command.append('--json')
        result = subprocess.run(command + list(args), text=True, capture_output=True,
                                encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, status, result.stderr + result.stdout)
        if json_output and result.stdout:
            return json.loads(result.stdout)
        return result

    def write(self, records, name='input.xml', encoding='utf-8', namespace=False):
        root = ET.Element('Events', {'xmlns': NS} if namespace else {})
        root.extend(records)
        path = self.root / name
        ET.ElementTree(root).write(path, encoding=encoding, xml_declaration=True)
        return str(path)

    def test_complete_investigation(self):
        parent_image = r'C:\Office\WINWORD.EXE'
        source = self.write([
            record(2, 1, 'powershell.exe', parent_image, 'powershell.exe -enc QQ=='),
            record(1, image=parent_image),
            record(3),
        ])
        imported = self.call('import', source)
        self.assertEqual(imported['inserted'], 3)
        self.assertEqual(self.call('scan')['alerts'], 2)
        alerts = self.call('alerts')['alerts']
        explanation = self.call('explain', str(alerts[0]['id']))
        self.assertEqual(len(explanation['ancestry']), 2)
        self.assertEqual(explanation['stop_reason'], 'parent_guid_missing')
        self.assertEqual(explanation['ancestry'][0]['sources'][0]['event_record_id'], '2')
        self.assertEqual(len(self.call('timeline', 'LAB')), 3)
        event_id = alerts[0]['event_id']
        self.assertEqual(len(self.call('tree', str(event_id))['ancestry']), 2)
        raw = self.call('event', str(event_id), '--raw', json_output=False).stdout
        self.assertEqual(ET.fromstring(raw).tag, 'EvidenceRecords')

    def test_import_and_scan_are_idempotent(self):
        source = self.write([record(1, image='powershell.exe', parent_image='WINWORD.EXE')])
        self.call('import', source)
        self.call('scan')
        before = self.call('alerts')
        self.assertEqual(self.call('import', source)['duplicates'], 1)
        self.assertTrue(self.call('stats')['scan_current'])
        self.call('scan')
        self.assertEqual(self.call('alerts'), before)
        self.assertEqual(self.call('stats')['source_records'], 1)

    def test_strict_import_does_not_create_or_modify_database(self):
        bad = record(2)
        bad.find("EventData/Data[@Name='ProcessId']").text = '-5'
        source = self.write([record(1), bad])
        result = self.call('import', source, '--strict', status=1)
        self.assertTrue(result['rejected'])
        self.assertFalse(self.db.exists())
        partial = self.call('import', source, status=1)
        self.assertEqual(partial['inserted'], 1)
        self.assertEqual(partial['diagnostics'][0]['ordinal'], 2)
        snapshot = self.db.read_bytes()
        self.call('import', source, '--strict', status=1)
        self.assertEqual(self.db.read_bytes(), snapshot)

    def test_freshness_changes_only_on_new_events(self):
        self.call('import', self.write([record(1)]))
        self.call('scan')
        self.call('import', self.write([record(2)], 'new.xml'))
        self.assertFalse(self.call('alerts')['scan_current'])
        self.call('scan')
        self.assertTrue(self.call('stats')['scan_current'])

    def test_namespaces_utf16_and_unicode_paths(self):
        source = self.write([record(1, command='notepad.exe "résumé.txt"')],
                            'données.xml', encoding='utf-16', namespace=True)
        db = self.root / 'résultats.db'
        self.assertEqual(self.call('import', source, db=db)['inserted'], 1)
        item = self.call('timeline', 'LAB', db=db)[0]
        self.assertIn('résumé', item['command_line'])
        raw = self.call('event', str(item['id']), '--raw', db=db, json_output=False).stdout
        self.assertEqual(ET.fromstring(raw)[0].tag, '{' + NS + '}Event')

    def test_prefixed_namespaces(self):
        source = self.write([record(1)])
        tree = ET.parse(source)
        for node in tree.iter():
            node.tag = '{' + NS + '}' + node.tag
        ET.register_namespace('w', NS)
        tree.write(source, encoding='utf-8')
        self.assertEqual(self.call('import', source)['inserted'], 1)
        raw = self.call('event', '1', '--raw', json_output=False).stdout
        ET.fromstring(raw)

    def test_sql_parameter_binding_and_conflicting_identity(self):
        source = self.write([record(1, command="x'; DROP TABLE events; --")])
        self.call('import', source)
        self.call('import', self.write([record(1, command='different')], 'conflict.xml'))
        stats = self.call('stats')
        self.assertEqual(stats['events'], 2)
        self.assertEqual(stats['identity_conflicts'], 1)
        tree = self.call('tree', '1')
        self.assertEqual(tree['stop_reason'], 'ambiguous_child_identity')

    def test_future_parent_is_not_invented(self):
        source = self.write([record(2, 1), record(1, timestamp='2026-09-10 00:00:00')])
        self.call('import', source)
        self.assertEqual(self.call('tree', '1')['stop_reason'], 'parent_timestamp_after_child')

    def test_missing_parent_still_allows_reported_field_rule(self):
        source = self.write([record(1, 999, 'powershell.exe', 'WINWORD.EXE')])
        self.call('import', source)
        self.call('scan')
        explanation = self.call('explain', '1')
        self.assertEqual(explanation['stop_reason'], 'parent_unobserved')
        self.assertEqual(explanation['alert']['matched_fields']['parent_basis'], 'reported_by_child_event')

    def test_unrelated_database_is_preserved(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE unrelated(value TEXT)')
        snapshot = self.db.read_bytes()
        self.call('import', self.write([record(1)]), status=1)
        self.assertEqual(self.db.read_bytes(), snapshot)

    def test_schema_version_is_checked(self):
        self.call('import', self.write([record(1)]))
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('PRAGMA user_version=999')
        self.call('stats', status=1)

    def test_failure_does_not_silently_create_database(self):
        self.call('scan', status=1)
        self.assertFalse(self.db.exists())
        self.call('unknown', status=2)
        self.call('event', '-1', status=2)
        self.call('stats', '--strict', status=2)
        self.assertFalse(self.db.exists())

    def test_malformed_document_does_not_commit_prefix(self):
        path = self.root / 'truncated.xml'
        path.write_text('<Events>' + ET.tostring(record(1), encoding='unicode') + '<Event>')
        self.call('import', str(path), status=1)
        self.assertFalse(self.db.exists())

    def test_all_rules_and_false_positive_boundaries(self):
        self.assertEqual(len(self.call('rules')), 3)
        source = self.write([
            record(1, image='wscript.exe', parent_image='excel.exe'),
            record(2, image='powershell.exe', command='powershell.exe -Command "echo -enc QQ=="'),
            record(3, image='powershell.exe.fake', parent_image='winword.exe'),
            record(4, image='pwsh.exe', command='pwsh.exe -EncodedCommand QQ=='),
        ])
        self.call('import', source)
        self.assertEqual(self.call('scan')['alerts'], 2)

    def test_database_capacity_failure_rolls_back_whole_import(self):
        self.call('import', self.write([record(1)]))
        # Populate the documented boundary directly to keep this a focused
        # transaction test, without generating a huge XML test fixture.
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("""WITH RECURSIVE n(x) AS (SELECT 2 UNION ALL SELECT x+1 FROM n WHERE x<250000)
                INSERT INTO events(identity,host,guid,time,pid,image)
                SELECT 'capacity-'||x,'capacity','capacity-'||x,'2026-09-09T00:00:00.000000000Z',x,'test.exe' FROM n""")
        before = self.call('stats')
        self.call('import', self.write([record(2)], 'extra.xml'), status=1)
        self.assertEqual(self.call('stats'), before)

    def test_terminal_controls_cannot_leak_from_command_lines(self):
        source = self.write([record(1, command='notepad.exe line1\nline2')])
        self.call('import', source)
        output = self.call('event', '1', json_output=False).stdout
        self.assertIn('line1\\u000aline2', output)

    def test_empty_and_unsupported_recording(self):
        other = record(1)
        other.find('System/EventID').text = '3'
        result = self.call('import', self.write([other]))
        self.assertEqual(result['unsupported'], 1)
        self.assertEqual(result['inserted'], 0)
        self.assertEqual(self.call('scan')['alerts'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
