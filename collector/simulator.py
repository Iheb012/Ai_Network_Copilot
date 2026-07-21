# collector/simulator.py
# Real network monitoring system that pings hosts and stores metrics
# Replaces the fake data generator with actual ping measurements

import random
import sqlite3
import datetime
import time
import subprocess
import re
import sys
import os

# Add the parent directory to path to import detection rules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'detection'))
from detection.rules import SEUILS

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def ping_host(host):
    """
    Ping a single host and return latency in ms and success boolean.
    On Windows, uses: ping -n 1 -w 1000 <host>
    Returns (latency_ms, success) where latency_ms is float or None if failed.
    """
    try:
        # Windows ping command: -n number of echoes, -w timeout in milliseconds
        # We'll do 1 echo with 1 second timeout
        output = subprocess.run(
            ['ping', '-n', '1', '-w', '1000', host],
            capture_output=True,
            text=True,
            timeout=2  # subprocess timeout slightly longer than ping timeout
        )
        if output.returncode == 0:
            # Search for time=XX ms pattern
            match = re.search(r'time[<=](\d+\.?\d*)\s*ms', output.text, re.IGNORECASE)
            if match:
                latency = float(match.group(1))
                return latency, True
            else:
                # Sometimes output may be different, but if returncode 0 assume success with default latency?
                # We'll treat as failure to be safe
                return None, False
        else:
            # Ping failed (host unreachable, etc.)
            return None, False
    except subprocess.TimeoutExpired:
        return None, False
    except Exception:
        return None, False

def generate_metrique_for_host(host):
    """
    Generate ONE line of data for a given host by pinging it.
    Returns a dict with metrics or None if ping failed completely.
    """
    latency, success = ping_host(host)

    if success and latency is not None:
        # Successful ping
        error_rate = 0.0  # No packet loss for single ping
        is_anomaly = 1 if (latency > SEUILS["latency"] or error_rate > SEUILS["error_rate"]) else 0
        print(f"🟢 {host}: latency={latency:.2f} ms")
    else:
        # Failed ping
        latency = None  # We'll store NULL or maybe a high value? We'll store None and handle in DB
        error_rate = 100.0  # 100% packet loss
        is_anomaly = 1  # Consider failure as anomaly
        print(f"🔴 {host}: PING FAILED")

    return {
        "ts": datetime.datetime.now().isoformat(),
        "host": host,
        "latency": latency,  # NULL if failed
        "error_rate": error_rate,
        "traffic": 0.0,      # Not measured by ping, set to 0
        "is_anomaly": is_anomaly
    }

def load_hosts_from_file(filename="hosts.txt"):
    """
    Load list of hosts from a text file, one per line.
    Ignores empty lines and lines starting with #.
    If file doesn't exist, returns a default list.
    """
    default_hosts = ["8.8.8.8", "1.1.1.1", "google.com", "github.com", "stackoverflow.com"]

    if not os.path.exists(filename):
        # Create default file
        with open(filename, 'w') as f:
            for host in default_hosts:
                f.write(host + '\n')
        return default_hosts

    hosts = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                hosts.append(line)

    if not hosts:
        return default_hosts
    return hosts

def sauvegarder(metrique):
    """
    Sauvegarde une métrique dans la base de données
    """
    connexion = sqlite3.connect(DB_PATH)
    curseur = connexion.cursor()

    curseur.execute("""
        INSERT INTO network_metrics
        (ts, host, latency, error_rate, traffic, is_anomaly)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        metrique["ts"],
        metrique["host"],
        metrique["latency"],
        metrique["error_rate"],
        metrique["traffic"],
        metrique["is_anomaly"]
    ))

    connexion.commit()
    connexion.close()

# Programme principal
if __name__ == "__main__":
    # On crée la base de données si elle n'existe pas
    from database import creer_base_de_donnees
    creer_base_de_donnees()

    # Load hosts to monitor
    hosts_file = os.path.join(os.path.dirname(__file__), "hosts.txt")
    hosts = load_hosts_from_file(hosts_file)

    print(f"🚀 Network Monitor démarré !")
    print(f"📡 Monitoring {len(hosts)} hosts: {', '.join(hosts)}")
    print("Appuie sur Ctrl+C pour arrêter\n")

    compteur = 0

    try:
        while True:
            compteur += 1
            print(f"--- Cycle #{compteur} ---")

            # Ping each host and store metrics
            for host in hosts:
                metrique = generate_metrique_for_host(host)
                if metrique is not None:
                    sauvegarder(metrique)
                print("   Sauvegardé !")

            print()  # Blank line between cycles

            # Wait before next cycle (default 5 seconds, can be made configurable)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n🛑 Network Monitor arrêté par l'utilisateur.")