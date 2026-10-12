-- Windows process, thread, service, and parent-child diagnostic model.
-- Target dialect: PostgreSQL 15 or later.
--
-- The schema stores time-bounded snapshots. Process IDs are not globally
-- unique and may be reused after exit, so identity is scoped to a snapshot.
-- This script models observations; it does not control operating-system state.

BEGIN;

DROP SCHEMA IF EXISTS windows_diagnostics CASCADE;
CREATE SCHEMA windows_diagnostics;
SET search_path TO windows_diagnostics, public;

CREATE TYPE process_observation_state AS ENUM (
    'observed',
    'exited',
    'access_denied',
    'metadata_unavailable'
);

CREATE TYPE service_runtime_state AS ENUM (
    'running',
    'stopped',
    'paused',
    'start_pending',
    'stop_pending',
    'unknown'
);

CREATE TABLE hosts (
    host_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name text NOT NULL UNIQUE,
    operating_system text NOT NULL DEFAULT 'Windows',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (btrim(host_name) <> '')
);

CREATE TABLE process_snapshots (
    snapshot_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id bigint NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    collector_name text NOT NULL,
    collection_complete boolean NOT NULL DEFAULT false,
    notes text,
    UNIQUE (host_id, snapshot_id),
    CHECK (btrim(collector_name) <> '')
);

CREATE TABLE processes (
    snapshot_id bigint NOT NULL REFERENCES process_snapshots(snapshot_id)
        ON DELETE CASCADE,
    pid integer NOT NULL,
    parent_pid integer,
    image_name text NOT NULL,
    thread_count integer NOT NULL DEFAULT 0,
    executable_path text,
    command_line text,
    observation_state process_observation_state NOT NULL DEFAULT 'observed',
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (snapshot_id, pid),
    CHECK (pid > 0),
    CHECK (parent_pid IS NULL OR parent_pid > 0),
    CHECK (parent_pid IS NULL OR parent_pid <> pid),
    CHECK (thread_count >= 0),
    CHECK (btrim(image_name) <> ''),
    CHECK (command_line IS NULL OR length(command_line) <= 32768)
);

-- This composite self-reference ensures that a recorded parent belongs to
-- the same snapshot. It is deferred so records can be inserted in any order.
-- Missing parents remain representable when the collector has a partial view;
-- the optional relationship is therefore validated by a separate query.
ALTER TABLE processes
    ADD CONSTRAINT processes_parent_fk
    FOREIGN KEY (snapshot_id, parent_pid)
    REFERENCES processes(snapshot_id, pid)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX processes_parent_idx
    ON processes(snapshot_id, parent_pid);

CREATE INDEX processes_thread_count_idx
    ON processes(snapshot_id, thread_count DESC);

CREATE INDEX processes_image_name_idx
    ON processes(image_name);

CREATE TABLE windows_services (
    snapshot_id bigint NOT NULL REFERENCES process_snapshots(snapshot_id)
        ON DELETE CASCADE,
    service_name text NOT NULL,
    display_name text NOT NULL,
    runtime_state service_runtime_state NOT NULL,
    start_mode text NOT NULL,
    process_id integer,
    service_account text,
    PRIMARY KEY (snapshot_id, service_name),
    CHECK (btrim(service_name) <> ''),
    CHECK (start_mode IN ('Auto', 'Manual', 'Disabled', 'Boot', 'System', 'Unknown')),
    CHECK (process_id IS NULL OR process_id > 0)
);

-- A service can share a host process with other services. The service PID
-- must exist in the same snapshot when non-null, but a service with PID NULL
-- may be stopped or otherwise unassigned.
ALTER TABLE windows_services
    ADD CONSTRAINT services_process_fk
    FOREIGN KEY (snapshot_id, process_id)
    REFERENCES processes(snapshot_id, pid)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX services_state_idx
    ON windows_services(snapshot_id, runtime_state);

CREATE TABLE process_threads (
    snapshot_id bigint NOT NULL,
    process_pid integer NOT NULL,
    thread_id bigint NOT NULL,
    start_address text,
    state text NOT NULL DEFAULT 'unknown',
    wait_reason text,
    PRIMARY KEY (snapshot_id, process_pid, thread_id),
    FOREIGN KEY (snapshot_id, process_pid)
        REFERENCES processes(snapshot_id, pid) ON DELETE CASCADE,
    CHECK (thread_id > 0),
    CHECK (state IN ('running', 'ready', 'waiting', 'terminated', 'unknown'))
);

CREATE INDEX process_threads_state_idx
    ON process_threads(snapshot_id, state);

CREATE TABLE diagnostic_findings (
    finding_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_id bigint NOT NULL REFERENCES process_snapshots(snapshot_id)
        ON DELETE CASCADE,
    process_pid integer,
    severity text NOT NULL,
    finding_code text NOT NULL,
    details text NOT NULL,
    detected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (severity IN ('info', 'warning', 'error')),
    CHECK (btrim(finding_code) <> ''),
    FOREIGN KEY (snapshot_id, process_pid)
        REFERENCES processes(snapshot_id, pid)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX findings_snapshot_severity_idx
    ON diagnostic_findings(snapshot_id, severity);

-- Demonstration data represents a workstation snapshot and a partial parent
-- observation. Parent PID 9999 is intentionally absent; it is not inserted as
-- a fabricated process record.
INSERT INTO hosts (host_name, operating_system)
VALUES ('DEV-WORKSTATION-01', 'Windows 11');

INSERT INTO process_snapshots (
    host_id, captured_at, collector_name, collection_complete, notes
)
SELECT host_id, clock_timestamp(), 'Win32_Process/CIM', false,
       'Illustrative inventory; parent metadata may be incomplete'
FROM hosts
WHERE host_name = 'DEV-WORKSTATION-01';

INSERT INTO processes (
    snapshot_id, pid, parent_pid, image_name, thread_count, executable_path
)
SELECT s.snapshot_id, data.pid, data.parent_pid, data.image_name,
       data.thread_count, data.executable_path
FROM process_snapshots s
JOIN hosts h ON h.host_id = s.host_id
CROSS JOIN (
    VALUES
        (4,    NULL::integer, 'System',                  180, NULL::text),
        (620,  4,             'services.exe',             12, 'C:\Windows\System32\services.exe'),
        (840,  620,           'svchost.exe',               28, NULL::text),
        (960,  620,           'svchost.exe',               34, NULL::text),
        (1200, 620,           'explorer.exe',              42, NULL::text),
        (1300, 1200,          'notepad.exe',                8, NULL::text),
        (1450, 1200,          'powershell.exe',            14, NULL::text),
        (1500, 1450,          'python.exe',                 6, NULL::text),
        (1700, 1200,          'chrome.exe',                31, NULL::text),
        (1710, 1700,          'chrome.exe',                16, NULL::text),
        (1720, 1700,          'chrome.exe',                22, NULL::text),
        (1900, 9999,          'diagnostic-worker.exe',      5, NULL::text)
) AS data(pid, parent_pid, image_name, thread_count, executable_path)
WHERE h.host_name = 'DEV-WORKSTATION-01';

INSERT INTO windows_services (
    snapshot_id, service_name, display_name, runtime_state,
    start_mode, process_id, service_account
)
SELECT s.snapshot_id, data.service_name, data.display_name,
       data.runtime_state::service_runtime_state, data.start_mode,
       data.process_id, data.service_account
FROM process_snapshots s
JOIN hosts h ON h.host_id = s.host_id
CROSS JOIN (
    VALUES
        ('ExampleTelemetry', 'Example Telemetry', 'running',
         'Auto', 840, 'LocalSystem'),
        ('ExampleWorker', 'Example Worker', 'running',
         'Manual', 960, 'NT AUTHORITY\LocalService'),
        ('ExampleUpdater', 'Example Updater', 'stopped',
         'Manual', NULL::integer, 'LocalSystem')
) AS data(
    service_name, display_name, runtime_state,
    start_mode, process_id, service_account
)
WHERE h.host_name = 'DEV-WORKSTATION-01';

INSERT INTO process_threads (
    snapshot_id, process_pid, thread_id, state, wait_reason
)
SELECT s.snapshot_id, data.process_pid, data.thread_id,
       data.state, data.wait_reason
FROM process_snapshots s
JOIN hosts h ON h.host_id = s.host_id
CROSS JOIN (
    VALUES
        (1500, 15001, 'running', 'none'),
        (1500, 15002, 'waiting', 'sleep'),
        (1700, 17001, 'running', 'none'),
        (1700, 17002, 'waiting', 'user_request'),
        (1200, 12001, 'waiting', 'input')
) AS data(process_pid, thread_id, state, wait_reason)
WHERE h.host_name = 'DEV-WORKSTATION-01';

-- Basic inventory: reported thread counts are process-level observations.
SELECT p.pid, p.image_name, p.parent_pid, p.thread_count, p.observation_state
FROM processes p
JOIN process_snapshots s USING (snapshot_id)
JOIN hosts h USING (host_id)
WHERE h.host_name = 'DEV-WORKSTATION-01'
ORDER BY p.pid;

-- Reconstruct direct parent-child relationships.
SELECT
    parent.pid AS parent_pid,
    parent.image_name AS parent_name,
    child.pid AS child_pid,
    child.image_name AS child_name
FROM processes child
JOIN processes parent
  ON parent.snapshot_id = child.snapshot_id
 AND parent.pid = child.parent_pid
ORDER BY parent.pid, child.pid;

-- Recursive ancestry query. UNION prevents repeated rows from a cyclic path,
-- while the path array explicitly prevents revisiting an already-seen PID.
WITH RECURSIVE process_tree AS (
    SELECT
        p.snapshot_id,
        p.pid,
        p.parent_pid,
        p.image_name,
        0 AS depth,
        ARRAY[p.pid] AS path
    FROM processes p
    JOIN process_snapshots s USING (snapshot_id)
    JOIN hosts h USING (host_id)
    WHERE h.host_name = 'DEV-WORKSTATION-01'
      AND p.pid = 1200

    UNION ALL

    SELECT
        child.snapshot_id,
        child.pid,
        child.parent_pid,
        child.image_name,
        tree.depth + 1,
        tree.path || child.pid
    FROM process_tree tree
    JOIN processes child
      ON child.snapshot_id = tree.snapshot_id
     AND child.parent_pid = tree.pid
    WHERE NOT child.pid = ANY(tree.path)
)
SELECT depth, pid, parent_pid, image_name, path
FROM process_tree
ORDER BY depth, pid;

-- Identify records whose parent was not observed. This is meaningful for
-- partial snapshots because a parent may have exited or be outside the view.
SELECT child.pid, child.image_name, child.parent_pid
FROM processes child
LEFT JOIN processes parent
  ON parent.snapshot_id = child.snapshot_id
 AND parent.pid = child.parent_pid
WHERE child.parent_pid IS NOT NULL
  AND parent.pid IS NULL;

-- Aggregate thread counts by process image. The result is descriptive, not a
-- measurement of CPU use; a large thread count does not prove high CPU load.
SELECT image_name,
       count(*) AS process_instances,
       sum(thread_count) AS reported_threads,
       max(thread_count) AS maximum_threads
FROM processes
GROUP BY image_name
ORDER BY reported_threads DESC, image_name;

-- Correlate service records with observed process names.
SELECT
    service.service_name,
    service.runtime_state,
    service.start_mode,
    service.process_id,
    process.image_name,
    CASE
        WHEN service.process_id IS NULL THEN 'no process assigned'
        WHEN process.pid IS NULL THEN 'process absent from snapshot'
        ELSE 'process observed'
    END AS correlation_status
FROM windows_services service
LEFT JOIN processes process
  ON process.snapshot_id = service.snapshot_id
 AND process.pid = service.process_id
ORDER BY service.service_name;

-- Demonstrate thread-level detail without assuming that every thread has
-- complete metadata. The thread table contains sampled examples only.
SELECT process.pid, process.image_name, thread.thread_id,
       thread.state, thread.wait_reason
FROM process_threads thread
JOIN processes process
  ON process.snapshot_id = thread.snapshot_id
 AND process.pid = thread.process_pid
ORDER BY process.pid, thread.thread_id;

-- Store findings for the incomplete parent record.
INSERT INTO diagnostic_findings (
    snapshot_id, process_pid, severity, finding_code, details
)
SELECT p.snapshot_id, p.pid, 'info', 'PARENT_NOT_OBSERVED',
       'Parent PID ' || p.parent_pid::text ||
       ' is absent from this snapshot; investigate snapshot completeness and PID reuse.'
FROM processes p
WHERE p.image_name = 'diagnostic-worker.exe'
  AND NOT EXISTS (
      SELECT 1
      FROM processes parent
      WHERE parent.snapshot_id = p.snapshot_id
        AND parent.pid = p.parent_pid
  );

SELECT finding_id, severity, finding_code, details
FROM diagnostic_findings
ORDER BY finding_id;

COMMIT;

-- Integrity demonstrations can be run separately because deliberate
-- constraint violations would abort the transaction:
--
-- Invalid PID:
-- INSERT INTO processes(snapshot_id, pid, image_name, thread_count)
-- SELECT snapshot_id, 0, 'invalid.exe', 1 FROM process_snapshots LIMIT 1;
--
-- Negative thread count:
-- INSERT INTO processes(snapshot_id, pid, image_name, thread_count)
-- SELECT snapshot_id, 20000, 'invalid.exe', -1 FROM process_snapshots LIMIT 1;
--
-- A process with itself as parent is prohibited by the CHECK constraint.
-- A non-null parent absent from the snapshot is prohibited by the deferred
-- foreign key. For incomplete inventories, store parent_pid as NULL when the
-- collector cannot reliably resolve it, and preserve uncertainty in findings.
