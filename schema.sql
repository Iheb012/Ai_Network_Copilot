-- Schema for network metrics database
CREATE TABLE IF NOT EXISTS network_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TIMESTAMP NOT NULL,
    host TEXT NOT NULL,
    latency REAL,          -- in milliseconds
    error_rate REAL,       -- percentage
    traffic REAL,          -- in Mbps or packets/sec
    is_anomaly BOOLEAN     -- 0 or 1
);
