# AI Network Copilot

A network monitoring and anomaly detection tool with real-time dashboard, automatic device discovery, fingerprinting, and ML-powered anomaly detection.

**Version:** 1.1.0

---

## Overview

AI Network Copilot continuously monitors your local network by:
- **Discovering** devices via ARP scanning, ping sweeps, and TCP probes
- **Pinging** every discovered host and collecting latency / error metrics
- **Detecting** anomalies using configurable business rules + a trained Isolation Forest ML model
- **Visualizing** everything in a real-time Streamlit dashboard with topology mapping, alert cards, and live WebSocket updates

---

## Project Structure

```
api/                         FastAPI backend (REST + WebSocket)
  main.py                    API server, endpoints, WebSocket manager
  database.py                SQLite database helpers
  detection_bridge.py        Bridge between API and detection module
  requirements.txt           fastapi, uvicorn, pydantic
  Dockerfile

collector/                   Network data collector
  simulator_v2.py            Main collector: ARP discovery, ping sweep, metric storage
  ping_collector.py          Lightweight ping collector (alternative)
  database.py                Database init helpers
  hosts.txt                  Default host list fallback
  requirements.txt           scapy, pysnmp

dashboard/                   Streamlit dashboard
  app.py                     Full dashboard with topology, alerts, KPIs, dark theme
  requirements.txt           streamlit, requests, pandas, plotly, streamlit-autorefresh
  Dockerfile
  static/                    Icons, background video assets

detection/                   Anomaly detection engine
  detecteur.py               Detection entry point: rules + ML + cause identification
  rules.py                   Business rule thresholds and adaptive thresholds
  ml_model.py                Isolation Forest model training
  exploration.py             Data exploration
  evaluation.py              Model evaluation
  model.pkl                  Pre-trained ML model

docs/                        Additional documentation
  schema_reseau.md           Network schema
  schema_donnees.md          Data schema

launcher.py                  Terminal launcher orchestrating all 3 services
updater.py                   GitHub release update checker
schema.sql                   Database schema (SQLite)
```

---

## Quick Start (Windows)

### 1. Create virtual environment & install dependencies

```batch
python -m venv venv
venv\Scripts\activate
pip install -r api\requirements.txt
pip install -r dashboard\requirements.txt
pip install -r collector\requirements.txt
```

### 2. Start all services

**Option A — App launcher (recommended):** double-click **`AI-Network-Copilot.exe`** in the project root.
It starts the collector, API and dashboard together and shows a small terminal UI for status / update checks.
The `.exe` wraps `launcher.py`; it is git-ignored (not committed), so rebuild it anytime with:

```batch
pyinstaller --onefile --name "AI-Network-Copilot" --icon dashboard/static/app-icon.ico launcher.py
```

**Option B — Python launcher (source):**
```batch
python launcher.py
```

**Option C — Manually (3 terminals):**

Terminal 1 — Collector:
```batch
cd collector
python simulator_v2.py
```

Terminal 2 — API:
```batch
cd api
uvicorn main:app --reload --port 8000
```

Terminal 3 — Dashboard:
```batch
cd dashboard
set API_BASE_URL=http://localhost:8000
set API_WS_BASE_URL=ws://localhost:8000
streamlit run app.py --server.port 8501
```

### 3. Open the dashboard

Navigate to **[http://localhost:8501](http://localhost:8501)**

---

## Access Points

| Service    | URL                              |
|------------|----------------------------------|
| Dashboard  | http://localhost:8501             |
| API        | http://localhost:8000             |
| API Docs   | http://localhost:8000/docs        |
| API Health | http://localhost:8000/health      |

---

## API Endpoints

### REST

| Method | Endpoint           | Description                         |
|--------|--------------------|-------------------------------------|
| GET    | `/metrics/latest`  | Latest network metrics              |
| GET    | `/alerts`          | Active alerts with anomaly causes   |
| GET    | `/hosts`           | List of unique hosts                |
| GET    | `/hosts/detail`    | Detailed host info                  |
| GET    | `/devices`         | All discovered devices              |
| GET    | `/topology`        | Network topology (nodes + links)    |
| GET    | `/ping/{host}`     | Ping a specific host in real time   |
| GET    | `/health`          | Health check                        |

### WebSocket

| Endpoint        | Description                          |
|-----------------|--------------------------------------|
| `/ws/metrics`   | Real-time metrics stream (every 5s)  |
| `/ws/alerts`    | Real-time alerts stream (every 5s)   |
| `/ws/topology`  | Real-time topology stream (every 10s)|

---

## Docker

```bash
# Build & run API
docker build -t ai-network-api -f api/Dockerfile .
docker run -p 8000:8000 ai-network-api

# Build & run Dashboard
docker build -t ai-network-dashboard ./dashboard
docker run -p 8501:8501 \
  -e API_BASE_URL=http://host.docker.internal:8000 \
  -e API_WS_BASE_URL=ws://host.docker.internal:8000 \
  ai-network-dashboard
```

---

## Dependencies

### API (`api/requirements.txt`)
- fastapi
- uvicorn
- pydantic
- pandas
- joblib
- scikit-learn
- ping3

### Dashboard (`dashboard/requirements.txt`)
- streamlit
- requests
- pandas
- plotly
- streamlit-autorefresh

### Collector (`collector/requirements.txt`)
- scapy >=2.4.5 (network discovery, ARP scanning)
- pysnmp >=4.4.0 (SNMP device interrogation, optional)

### Detection (installed alongside collector/api)
- joblib (ML model loading)
- pandas (data processing)
- scikit-learn (Isolation Forest model)

---

## Features

- **Automatic network discovery** — scans all local subnets using ARP, ping sweeps, TCP probes, and Windows neighbor cache
- **Device fingerprinting** — identifies device type, vendor, and hostname via MAC OUI lookup, port scanning, and reverse DNS
- **Anomaly detection** — dual-layer detection using configurable business rules (latency/error thresholds) + Isolation Forest ML model with cause identification and confidence scoring
- **Real-time dashboard** — Streamlit UI with KPI cards, topology graph, alert panels, manual ping tool, and auto-refresh
- **Live updates** — WebSocket connections push metrics, alerts, and topology changes to the dashboard every 5-10 seconds
- **Phone hotspot detection** — automatically detects phone hotspot networks and disables topology visualization
- **Self-updating** — `updater.py` checks GitHub releases for new versions
- **Dark space-themed UI** — animated black hole video background, shooting star effects, glowing gradient accents

---

## Launcher Commands

When running `launcher.py`, use these commands:

| Command | Action                  |
|---------|-------------------------|
| `S`     | Show service status     |
| `U`     | Check for updates       |
| `Q`     | Quit / shutdown all     |

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Collector     │────>│    FastAPI        │<───>│   Streamlit     │
│ (simulator_v2)  │     │    (api/main.py)  │     │   Dashboard     │
│                 │     │                   │     │                 │
│ Ping + ARP scan │     │ REST + WebSocket  │     │ Visualizations  │
│ Network metrics │     │ Detection bridge  │     │ Topology graph  │
│ Device discovery│     │                   │     │ Alert panels    │
└────────┬────────┘     └────────┬──────────┘     └────────┬────────┘
         │                       │                         │
         └─────── SQLite ────────┴──────── SQLite ─────────┘
                     (data/network.db)

┌─────────────────────┐
│   Detection Engine   │
│  (detection/detecteur.py)
│                       │
│  Rules + ML model    │
│  Cause identification │
└───────────────────────┘
```

---

## Database

The project uses SQLite (`data/network.db`). Schema in `schema.sql`:

```sql
CREATE TABLE network_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TIMESTAMP NOT NULL,
    host TEXT NOT NULL,
    latency REAL,
    error_rate REAL,
    traffic REAL,
    is_anomaly BOOLEAN
);
```

---

## Development Notes

- Built as a 4-week internship project (Personne A = Data/ML, Personne B = Backend/Dashboard)
- Scapy ARP scanning may need the Npcap/WinPcap driver on Windows
- The pre-trained ML model (`detection/model.pkl`) can be retrained by running `detection/ml_model.py`
- Custom device type overrides can be set in `dashboard/app.py` (`_DEVICE_TYPE_OVERRIDES` dict)

---

## Security

- **API key authentication.** Every API endpoint (REST and WebSocket) requires an API key, except `/health` and `/docs`. The launcher creates a random key in `data/.api_key` on first run (git-ignored) and shares it with the API, dashboard and collector automatically. To use your own key, set the `AI_COPILOT_API_KEY` environment variable. REST clients send it as an `X-API-Key` header; WebSockets use `?api_key=<key>`.
- **Docker:** set the same `AI_COPILOT_API_KEY` for the API and dashboard containers, and build the API image from the repo root: `docker build -f api/Dockerfile .`
- **Local only by default.** The launcher binds the API and dashboard to `127.0.0.1`. Set `AI_COPILOT_HOST=0.0.0.0` to allow other devices (trusted networks only: the dashboard page embeds the key).
- **Network interface.** The ARP scan interface is auto-detected. Override it with the `SCAPY_IFACE` environment variable if needed.
- **`/ping/{host}`** sends real ICMP probes (4 packets). An unreachable host is reported as unreachable (`latency: null`, `error_rate: 100`); no data is simulated.
- **ML model.** `detection/model.pkl` was trained with scikit-learn 1.9.0, which is pinned in `api/requirements.txt`. If you change the version, retrain with `detection/ml_model.py`.
- **Device discovery.** Devices come only from real network discovery (ARP scan, or ping sweep + neighbour table when not running as root). `hosts.txt` is used only when you pass `--use-file`. On a VirtualBox VM use **Bridged Adapter** networking, otherwise the VM only sees its own virtual NAT network.
- **Performance.** On virtual machines or computers without GPU acceleration, start with `python launcher.py --lite` (or set `AI_COPILOT_LITE=1`) to disable the 3D background and blur effects.
