# Design decisions

## Keep collection outside the analysis core

Sysmon already records process creation. This release consumes saved XML so
import, detection, and investigation can be tested deterministically. No event
is executed. There is one event model for the supported process-creation type;
no general plugin framework or unused abstraction is introduced.

## Separate event identity from source identity

A process creation may appear in multiple exports. Deduplication uses a
collision-free, length-prefixed representation of canonical host and EventData,
not a noncryptographic hash. All EventData fields participate, including fields
the current event model does not interpret. The unique SQLite index enforces
this identity across sessions. Original export paths and record numbers are
stored separately, together with serialized evidence XML.

This policy is deliberately conservative: missing versus present fields, or
changes to unmodeled fields, may produce distinct records for one process GUID.
Those records remain visible as identity conflicts. The importer does not
invent a reconciliation rule. Two identical normalized process records with
different EventRecordIDs deduplicate, retaining both source references.

The source-reference unique index includes serialized XML. This consumes disk
space but preserves altered source representations without relying on a digest
implementation or overwriting previous evidence. The benchmark records the
resulting database size. A future schema migration could normalize evidence
blobs if measured workload sizes justify it.

## Make incomplete ancestry explicit

The in-memory index maps canonical `(host, process_guid)` to candidate records.
One candidate can resolve a parent; multiple candidates stop resolution. All
records are indexed before traversal, so input order does not affect parent
availability. A parent recorded after the child in the file is valid if its
creation time is earlier or equal. A parent with a later creation timestamp,
contradictory PID or image, missing GUID, or conflicting identity is unresolved.
Host aliases are not merged. PIDs never substitute for GUIDs.

Traversal tracks visited process keys and has a fixed depth limit. Detection
matches reported fields in the child independently of resolution. The alert
states this evidence basis; an unresolved parent never becomes a fabricated
observed event.

## Transactional persistence

SQLite connection and statement lifetimes use RAII. The transaction guard rolls
back if an operation throws. Imports and scans take an immediate write
transaction with a five-second busy timeout. SQLite's durable default journal
and synchronization settings are retained. The application does not disable
synchronization to improve benchmark numbers.

Schema ownership uses an application ID and schema version. An unrelated or
future-version database is rejected. Read commands open SQLite read-only and
hold one read transaction across the investigation. New event imports advance
the generation counter; repeated exports do not. A scan stores its generation
and engine version atomically with its alerts. The CLI reports freshness.

The core database API expects normalized `import_batch` values from the importer.
Callers must not construct arbitrary invalid batches. `begin_read()` establishes
a snapshot for a read-only session until destruction; do not mix it with write
methods on that connection.

## Optimize the measured path

Import reuses prepared statements and commits once. Scanning loads normalized
fields without raw XML, evaluates a fixed rule set once, and reuses its alert
upsert statement. Ancestry lookup uses a reserved hash table. Host timelines use
an indexed SQL query. Parsing, storage, and detection remain synchronous because
introducing threads would complicate error handling and transaction ownership
without evidence of a throughput requirement.

The DOM importer and batch vector require memory proportional to input size.
The input byte limit bounds exposure but is not a process RSS cap: XML tree,
strings and indexes can consume several times the source size. Large enterprise
log archives should be split into separate cases. There is no streaming or
unbounded-data claim.

## Rule changes

The built-in catalog documents a rule ID, revision, rationale, severity and
likely false positives. Change the rule revision when matching semantics
change, and change the application version for a new release so stored scan
freshness is invalidated. Scan reconciles findings atomically; obsolete rule
revisions are removed after their replacements are inserted. Alert IDs remain
stable for an unchanged event/rule/revision.

The encoded-command detector is a lexical heuristic covering the explicitly
listed switches. It does not model every PowerShell abbreviation, escaping
rule, executable-launch convention or shell expansion. That limit is documented
instead of claiming full syntax understanding.
