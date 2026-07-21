# collector/database.py
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def creer_base_de_donnees():
    """
    Crée la base de données et les tables network_metrics et device_properties
    selon le schéma défini avec Personne B
    """
    print(f"Connecting to database at: {DB_PATH}")

    connexion = sqlite3.connect(DB_PATH)
    curseur = connexion.cursor()

    # Create network_metrics table
    curseur.execute("""
        CREATE TABLE IF NOT EXISTS network_metrics (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TIMESTAMP NOT NULL,
            host       TEXT NOT NULL,
            latency    REAL,
            error_rate REAL,
            traffic    REAL,
            is_anomaly BOOLEAN,
            mac        TEXT
        )
    """)

    # Migrate old schema: rename trafic -> traffic if column exists
    try:
        curseur.execute("ALTER TABLE network_metrics RENAME COLUMN trafic TO traffic")
        print("   [migrate] Renamed column 'trafic' -> 'traffic'")
    except sqlite3.OperationalError:
        pass  # column either already renamed or never existed
    # Add mac column if missing
    try:
        curseur.execute("ALTER TABLE network_metrics ADD COLUMN mac TEXT")
        print("   [migrate] Added 'mac' column")
    except sqlite3.OperationalError:
        pass  # column already exists

    # Create device_properties table
    curseur.execute("""
        CREATE TABLE IF NOT EXISTS device_properties (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip      TEXT NOT NULL,
            property_key   TEXT NOT NULL,
            value          TEXT,
            updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_ip, property_key)
        )
    """)

    connexion.commit()
    connexion.close()
    print("Base de données prête !")


def save_device_properties(device_ip: str, properties: dict):
    """Save or update properties for a device"""
    import json

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure device_properties table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_properties (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip      TEXT NOT NULL,
            property_key   TEXT NOT NULL,
            value          TEXT,  -- JSON encoded value
            updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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


def cleanup_stale_devices(active_ips: list):
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