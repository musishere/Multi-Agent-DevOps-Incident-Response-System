CREATE TABLE services (
    service_name TEXT PRIMARY KEY,
    criticality  TEXT NOT NULL,
    owner_team   TEXT NOT NULL
);

CREATE TABLE metrics (
    id              SERIAL PRIMARY KEY,
    service         TEXT NOT NULL,
    p99_latency_ms  INTEGER NOT NULL,
    error_rate      REAL NOT NULL,
    cpu_percent     INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL
);

-- Legacy log export: deliberately different field names than metrics (svc_name, date as text)
CREATE TABLE logs (
    id       SERIAL PRIMARY KEY,
    svc_name TEXT NOT NULL,
    level    TEXT NOT NULL,
    message  TEXT NOT NULL,
    err_count INTEGER NOT NULL,
    date     TEXT NOT NULL
);

CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    service     TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE incident_updates (
    id          SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    message     TEXT NOT NULL,
    posted_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE remediation_log (
    id        SERIAL PRIMARY KEY,
    service   TEXT NOT NULL,
    action    TEXT NOT NULL,
    status    TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL
);
