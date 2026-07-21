"""
Database utility functions for AI Network Copilot API
"""
import sqlite3
import datetime
import os
import json
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

class NetworkMetric(BaseModel):
    ts: datetime.datetime
    host: str
    latency: Optional[float] = None
    error_rate: Optional[float] = None
    traffic: Optional[float] = None
    is_anomaly: bool
    mac: Optional[str] = None  # MAC address, if available

def get_latest_metrics(limit: int = 100) -> List[NetworkMetric]:
    """Get latest network metrics from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ts, host, latency, error_rate, traffic, is_anomaly, mac
        FROM network_metrics
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    metrics = []
    for row in rows:
        metrics.append(NetworkMetric(
            ts=datetime.datetime.fromisoformat(row['ts']),
            host=row['host'],
            latency=row['latency'],
            error_rate=row['error_rate'],
            traffic=row['traffic'],
            is_anomaly=bool(row['is_anomaly']),
            mac=row['mac']
        ))

    return metrics

def get_alerts(limit: int = 50) -> List[dict]:
    """Get active alerts (anomalies) from database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ts, host,
               CASE
                   WHEN latency > 100 THEN 'High latency'
                   WHEN error_rate > 5 THEN 'High error rate'
                   WHEN traffic > 90 THEN 'High traffic'
                   ELSE 'Network anomaly'
               END as reason
        FROM network_metrics
        WHERE is_anomaly = 1
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "ts": datetime.datetime.fromisoformat(row['ts']),
            "host": row['host'],
            "reason": row['reason']
        })

    return alerts

def get_hosts() -> List[str]:
    """Get list of unique hosts in the database"""
    # Test comment to verify edit capability
    # This is a test comment
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT host FROM network_metrics ORDER BY host")
    rows = cursor.fetchall()
    conn.close()

    return [row[0] for row in rows]

def get_hosts_detail() -> List[dict]:
    """Get detailed information for each host: latest MAC and last seen timestamp"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # For each host, get the most recent record's mac and ts
    cursor.execute("""
        SELECT host,
               MAX(ts) as last_seen,
               (SELECT mac FROM network_metrics n2
                WHERE n2.host = n1.host AND n2.mac IS NOT NULL
                ORDER BY ts DESC LIMIT 1) as latest_mac
        FROM network_metrics n1
        GROUP BY host
        ORDER BY host
    """)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "host": row["host"],
            "last_seen": datetime.datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            "mac": row["latest_mac"]
        })
    return result

def get_latest_mac_for_host(host: str) -> Optional[str]:
    """Get the most recent MAC address for a given host"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT mac FROM network_metrics
        WHERE host = ? AND mac IS NOT NULL  -- Fixed
        ORDER BY ts DESC
        LIMIT 1
    """, (host,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def save_device_properties(device_ip: str, properties: Dict[str, Any]):
    """Save or update properties for a device"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure device_properties table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            property_key TEXT NOT NULL,
            value TEXT,  -- JSON encoded value
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_ip, property_key)
        )
    """)

    # Insert or update each property
    for key, value in properties.items():
        # Convert value to JSON string for storage
        json_value = json.dumps(value) if not isinstance(value, str) else value
        cursor.execute("""
            INSERT OR REPLACE INTO device_properties (device_ip, property_key, value, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (device_ip, key, json_value))

    conn.commit()
    conn.close()


def cleanup_stale_devices(active_ips: List[str]):
    """Remove all traces of devices no longer on the network."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    placeholders = ",".join("?" for _ in active_ips) if active_ips else "''"

    cursor.execute(f"""
        DELETE FROM device_properties
        WHERE device_ip NOT IN ({placeholders})
    """, active_ips)
    dp_deleted = cursor.rowcount

    cursor.execute(f"""
        DELETE FROM network_metrics
        WHERE host NOT IN ({placeholders})
    """, active_ips)
    nm_deleted = cursor.rowcount

    if dp_deleted or nm_deleted:
        print(f"   [cleanup] Removed {dp_deleted} property rows + {nm_deleted} metric rows for stale devices")
    conn.commit()
    conn.close()


def get_device_properties(device_ip: str) -> Dict[str, Any]:
    """Get all properties for a device"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            property_key TEXT NOT NULL,
            value TEXT,  -- JSON encoded value
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_ip, property_key)
        )
    """)

    cursor.execute("""
        SELECT property_key, value
        FROM device_properties
        WHERE device_ip = ?
    """, (device_ip,))

    rows = cursor.fetchall()
    conn.close()

    # Parse JSON values back to Python objects
    properties = {}
    for key, value in rows:
        try:
            properties[key] = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            properties[key] = value  # Return as string if not valid JSON

    return properties


def creer_base_de_donnees():
    """Create the database and tables if they do not exist, ensure MAC column exists"""
    # Ensure the data directory exists
    data_dir = "../data"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create network_metrics table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP NOT NULL,
            host TEXT NOT NULL,
            latency REAL,          -- in milliseconds
            error_rate REAL,       -- percentage
            traffic REAL,          -- in Mbps or packets/sec
            is_anomaly BOOLEAN,    -- 0 or 1
            mac TEXT               -- MAC address, if available
        )
    """)

    # Create device_properties table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            property_key TEXT NOT NULL,
            value TEXT,  -- JSON encoded value
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_ip, property_key)
        )
    """)

    # Try to add the MAC column if it doesn't exist (for existing databases)
    try:
        cursor.execute("ALTER TABLE network_metrics ADD COLUMN mac TEXT")
    except sqlite3.OperationalError as e:
        # Column likely already exists, which is fine
        if "duplicate column name" not in str(e):
            raise  # Re-raise if it's a different error

    # Create indexes for better performance
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_network_metrics_host_ts
        ON network_metrics(host, ts DESC)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_device_properties_device_ip
        ON device_properties(device_ip)
    """)

    conn.commit()
    conn.close()

def get_devices(live_only: bool = True, max_age_minutes: int = 5) -> List[dict]:
    """Get discovered devices with their properties.
    By default (live_only=True) only returns devices with metrics
    seen in the last `max_age_minutes` minutes — this gives a live
    topology that excludes offline/stale devices from previous runs."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ── Find recently active hosts from metrics ──
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(minutes=max_age_minutes)).isoformat()
    cursor.execute("""
        SELECT DISTINCT m.host, MAX(m.ts) AS last_seen
        FROM network_metrics m
        WHERE m.ts >= ?
        GROUP BY m.host
        ORDER BY last_seen DESC
    """, (cutoff,))
    recent_rows = cursor.fetchall()
    recent_ips = {r["host"] for r in recent_rows}
    last_seen_map = {r["host"]: r["last_seen"] for r in recent_rows}

    if not recent_ips:
        conn.close()
        return []

    # ── Build device list from recently active hosts ──
    devices = []
    for host in recent_ips:
        # Get latest MAC for this host
        cursor.execute("""
            SELECT mac FROM network_metrics
            WHERE host = ? AND mac IS NOT NULL
            ORDER BY ts DESC LIMIT 1
        """, (host,))
        mac_row = cursor.fetchone()
        mac = mac_row[0] if mac_row else None

        # Fetch saved device properties (key-value store)
        cursor.execute("""
            SELECT property_key, value FROM device_properties
            WHERE device_ip = ?
        """, (host,))
        prop_rows = cursor.fetchall()
        properties = {}
        for pk, pv in prop_rows:
            try:
                import json
                properties[pk] = json.loads(pv)
            except Exception:
                properties[pk] = pv

        # Aggregate metrics for this host within the live window
        cursor.execute("""
            SELECT
                AVG(latency)      AS avg_latency,
                AVG(error_rate)   AS avg_error_rate,
                SUM(is_anomaly)   AS anomaly_count,
                COUNT(*)          AS total_samples
            FROM network_metrics
            WHERE host = ? AND ts >= ?
        """, (host, cutoff))
        agg = cursor.fetchone()

        devices.append({
            "ip":             host,
            "mac":            mac or properties.get("mac"),
            "last_seen":      last_seen_map.get(host),
            "avg_latency":    round(agg["avg_latency"]    or 0, 2),
            "avg_error_rate": round(agg["avg_error_rate"] or 0, 2),
            "anomaly_count":  int(agg["anomaly_count"]    or 0),
            "total_samples":  int(agg["total_samples"]    or 0),
            "vendor":         properties.get("vendor", "Unknown"),
            "hostname":       properties.get("hostname"),
            "device_type":    properties.get("device_type", "Unknown"),
        })

    conn.close()
    return devices