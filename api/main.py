from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Set
import datetime
import logging
import sys
import os
import asyncio
import json
import re
import ping3
from starlette.concurrency import run_in_threadpool

# Add the api directory and project root to the path so we can import database and detection
api_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(api_dir)
project_root = os.path.dirname(api_dir)
sys.path.append(project_root)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from security import require_api_key

app = FastAPI(
    title="AI Network Copilot API",
    description="API for network metrics and alerts",
    version="0.1.0",
    dependencies=[Depends(require_api_key)],
)

# Connection manager for WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, set[WebSocket]] = {
            "metrics": set(),
            "alerts": set(),
            "topology": set()
        }

    async def connect(self, websocket: WebSocket, stream_type: str):
        await websocket.accept()
        self.active_connections[stream_type].add(websocket)

    def disconnect(self, websocket: WebSocket, stream_type: str):
        self.active_connections[stream_type].discard(websocket)

    async def broadcast(self, message: dict, stream_type: str):
        for connection in self.active_connections[stream_type].copy():
            try:
                await connection.send_json(message)
            except:
                # Remove broken connections
                self.active_connections[stream_type].discard(connection)


manager = ConnectionManager()

# Import database utility
from database import get_hosts as db_get_hosts, get_hosts_detail as db_get_hosts_detail, creer_base_de_donnees

# Known phone hotspot subnets
HOTSPOT_SUBNETS = [
    "192.168.42.",  # Android
    "192.168.43.",  # Android
    "192.168.44.",  # Android (some variants)
    "172.20.10.",   # iPhone/iPad hotspot
]

def _is_hotspot_network(devices):
    """Detect if the current network is a phone hotspot based on device IPs.

    Returns True if the machine's own IP (Copilot Host) OR the gateway (Router)
    is on a known phone-hotspot subnet, or if the majority of devices are.
    Checking self/gateway makes the detection reliable even when AP isolation
    only exposes the host machine to the collector."""
    if not devices:
        return False

    def _on_hotspot_subnet(ip):
        return any(ip.startswith(prefix) for prefix in HOTSPOT_SUBNETS)

    hotspot_count = 0
    for d in devices:
        ip = d.get("ip", "")
        if _on_hotspot_subnet(ip):
            hotspot_count += 1
            dtype = d.get("device_type") or ""
            # The machine itself or its gateway on a hotspot subnet is decisive
            if "Copilot Host" in dtype or dtype == "Router":
                return True
    # Fallback: majority of devices on a hotspot subnet
    return hotspot_count > len(devices) / 2

# Import detection bridge (Personne A's ML engine — replaces raw DB queries)
from detection_bridge import get_alerts_with_causes, get_metrics_with_detection, analyser_metrique_temps_reel

def _is_safe_ping_target(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\.\-:]*", host) is not None

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        creer_base_de_donnees()
        logger.info("Database initialized/verified successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


# WebSocket endpoints for real-time updates
@app.websocket("/ws/metrics")
async def websocket_metrics_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics updates"""
    await manager.connect(websocket, "metrics")
    try:
        while True:
            # Send latest metrics every 5 seconds
            await asyncio.sleep(5)
            try:
                metrics = get_metrics_with_detection(limit=10)
                await websocket.send_json({
                    "type": "metrics_update",
                    "data": metrics,
                    "timestamp": datetime.datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending metrics update: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": "Failed to fetch metrics"
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket, "metrics")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, "metrics")


@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts updates"""
    await manager.connect(websocket, "alerts")
    try:
        while True:
            # Send latest alerts every 5 seconds
            await asyncio.sleep(5)
            try:
                alerts = get_alerts_with_causes(limit=10)
                await websocket.send_json({
                    "type": "alerts_update",
                    "data": alerts,
                    "timestamp": datetime.datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending alerts update: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": "Failed to fetch alerts"
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, "alerts")


def _ip_sort_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 0, 0, 0)


def _pick_hub(devices):
    """The device everything hangs off: the real default gateway if the collector
    tagged one, else any Router, else the lowest IP. Deterministic, so the
    topology does not reshuffle between refreshes."""
    ordered = sorted((d for d in devices if d.get("ip")), key=lambda d: _ip_sort_key(d["ip"]))
    for d in ordered:
        if d.get("vendor") == "Gateway":
            return d
    for d in ordered:
        if "Router" in (d.get("device_type") or ""):
            return d
    return ordered[0] if ordered else None


def _topology_links(devices):
    """Hub-and-spoke links (gateway to every other device). The old code linked
    every pair in the subnet, which is N*(N-1)/2 links and not a real topology."""
    hub = _pick_hub(devices)
    if not hub:
        return []
    return [{"source": hub["ip"], "target": d["ip"], "label": "", "type": "ethernet"}
            for d in sorted((x for x in devices if x.get("ip") and x["ip"] != hub["ip"]),
                            key=lambda x: _ip_sort_key(x["ip"]))]


@app.websocket("/ws/topology")
async def websocket_topology_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time topology updates"""
    await manager.connect(websocket, "topology")
    try:
        while True:
            # Send topology updates every 10 seconds (less frequent as topology changes less often)
            await asyncio.sleep(10)
            try:
                from database import get_devices
                devices = get_devices()

                # ── Phone hotspot detection ──
                if _is_hotspot_network(devices):
                    await websocket.send_json({
                        "type": "topology_update",
                        "data": {
                            "hotspot_detected": True,
                            "message": "Phone hotspot detected. Topology is not available.",
                            "nodes": [],
                            "links": []
                        },
                        "timestamp": datetime.datetime.now().isoformat()
                    })
                    continue

                # Build topology data (same logic as in /topology endpoint)
                nodes = []
                links = []

                # Create nodes for each device
                for i, device in enumerate(devices):
                    # Determine node color based on device type and status
                    color = "#4CAF50"  # Default green (online)
                    dtype = device.get("device_type", "Unknown") or "Unknown"
                    if dtype == "Unknown":
                        color = "#9E9E9E"  # Grey for unknown
                    elif "Router" in dtype or "Switch" in dtype:
                        color = "#2196F3"  # Blue for network devices
                    elif "Server" in dtype:
                        color = "#FF9800"  # Orange for servers

                    node = {
                        "id": device["ip"],
                        "label": device.get("hostname") or device["ip"],
                        "ip": device["ip"],
                        "mac": device.get("mac") or "",
                        "vendor": device.get("vendor") or "Unknown",
                        "device_type": dtype,
                        "status": "online",  # We'll determine this based on recent ping success
                        "color": color,
                        "size": 20 if ("Router" in dtype or "Switch" in dtype) else 15
                    }
                    nodes.append(node)

                links = _topology_links(devices)

                await websocket.send_json({
                    "type": "topology_update",
                    "data": {"nodes": nodes, "links": links},
                    "timestamp": datetime.datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending topology update: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": "Failed to fetch topology data"
                })
    except WebSocketDisconnect:
        manager.disconnect(websocket, "topology")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, "topology")


# Pydantic models for response
class NetworkMetric(BaseModel):
    ts: datetime.datetime
    host: str
    latency: Optional[float] = None
    error_rate: Optional[float] = None
    traffic: Optional[float] = None
    is_anomaly: bool

class MetricsResponse(BaseModel):
    metrics: List[NetworkMetric]

class Alert(BaseModel):
    ts: datetime.datetime
    host: str
    reason: str

class AlertsResponse(BaseModel):
    alerts: List[Alert]

class HostsResponse(BaseModel):
    hosts: List[str]

class PingResult(BaseModel):
    host: str
    latency: Optional[float] = None
    error_rate: Optional[float] = None
    traffic: float = 0.0
    is_anomaly: bool
    ts: datetime.datetime

@app.get("/metrics/latest", response_model=MetricsResponse)
async def get_latest_metrics_endpoint(limit: int = 100):
    """Get latest network metrics"""
    logger.info(f"Fetching latest {limit} network metrics")
    try:
        metrics = get_metrics_with_detection(limit)
        return {"metrics": metrics}
    except Exception as e:
        logger.error(f"Error fetching metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch metrics")

@app.get("/alerts", response_model=AlertsResponse)
async def get_alerts_endpoint(limit: int = 50):
    """Get active alerts"""
    logger.info(f"Fetching latest {limit} alerts")
    try:
        alerts = get_alerts_with_causes(limit)
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch alerts")

@app.get("/health")
async def health_endpoint():
    """Simple liveness probe (referenced by the launcher)."""
    return {"status": "ok"}

@app.get("/hosts", response_model=HostsResponse)
async def get_hosts_endpoint():
    """Get list of unique hosts"""
    logger.info("Fetching unique hosts")
    try:
        hosts = db_get_hosts()
        return {"hosts": hosts}
    except Exception as e:
        logger.error(f"Error fetching hosts: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch hosts")



PING_PROBES = 4          # packets sent per request
PING_TIMEOUT_S = 1       # seconds to wait for each reply


def _measure_host(target: str):
    """Send real ICMP probes. Returns (avg_latency_ms | None, loss_percent)."""
    latencies = []
    for _ in range(PING_PROBES):
        try:
            rtt = ping3.ping(target, timeout=PING_TIMEOUT_S)
        except Exception:
            rtt = None
        # ping3 returns seconds on success, None on timeout, False on error
        if rtt is not None and rtt is not False:
            latencies.append(float(rtt) * 1000)
    loss = (PING_PROBES - len(latencies)) / PING_PROBES * 100
    avg = round(sum(latencies) / len(latencies), 2) if latencies else None
    return avg, round(loss, 1)


@app.get("/ping/{host}", response_model=PingResult)
async def ping_host_endpoint(host: str):
    """Ping a host with real ICMP probes and return the measured result.

    Nothing is simulated: an unreachable host is reported as unreachable
    (latency null, error_rate 100). Traffic is not measured by ping, so it is 0.
    """
    logger.info(f"Pinging host: {host}")
    if not _is_safe_ping_target(host):
        raise HTTPException(status_code=400, detail="Invalid host format")

    latency, error_rate = await run_in_threadpool(_measure_host, host)
    traffic = 0.0

    try:
        detection = analyser_metrique_temps_reel(latency or 0, error_rate, traffic)
        is_anomaly = detection["is_anomaly"]
        logger.info(
            f"Detection for {host}: "
            f"{'ANOMALY' if is_anomaly else 'OK'} | "
            f"Cause: {detection['description']} | "
            f"Confiance: {detection['score_confiance']}%"
        )
    except Exception as e:
        logger.warning(f"ML engine unavailable ({e}); using threshold fallback")
        is_anomaly = (latency or 0) > 150 or error_rate > 5

    return PingResult(
        host=host,
        latency=latency,
        error_rate=error_rate,
        traffic=traffic,
        is_anomaly=bool(is_anomaly),
        ts=datetime.datetime.now(),
    )


@app.get("/hosts/detail")
async def get_hosts_detail_endpoint():
    """Get detailed information for each host"""
    logger.info("Fetching host details")
    try:
        details = db_get_hosts_detail()
        return {"hosts": details}
    except Exception as e:
        logger.error(f"Error fetching host details: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch host details")

@app.get("/devices")
async def get_devices_endpoint():
    """Get detailed information for all discovered devices"""
    logger.info("Fetching device information")
    try:
        from database import get_devices
        devices = get_devices()
        # Convert to dict for JSON serialization
        return {"devices": devices}  # already plain dicts from get_devices()
    except Exception as e:
        logger.error(f"Error fetching device information: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch device information")

@app.get("/topology")
async def get_topology_endpoint():
    """Get network topology data for visualization"""
    logger.info("Fetching network topology")
    try:
        from database import get_devices
        devices = get_devices()

        # ── Phone hotspot detection ──
        if _is_hotspot_network(devices):
            logger.warning("Phone hotspot network detected — topology not available")
            return {
                "hotspot_detected": True,
                "message": "Phone hotspot detected. Topology is not available for this network type.",
                "nodes": [],
                "links": []
            }

        # Build topology data
        nodes = []
        links = []

        # Create nodes for each device (devices are plain dicts)
        for device in devices:
            dtype = device.get("device_type", "Unknown") or "Unknown"
            color = "#4CAF50"
            if dtype == "Unknown":
                color = "#9E9E9E"
            elif "Router" in dtype or "Switch" in dtype:
                color = "#2196F3"
            elif "Server" in dtype:
                color = "#FF9800"

            node = {
                "id":          device["ip"],
                "label":       device.get("hostname") or device["ip"],
                "ip":          device["ip"],
                "mac":         device.get("mac") or "",
                "vendor":      device.get("vendor") or "Unknown",
                "device_type": dtype,
                "status":      "online",
                "color":       color,
                "size":        20 if ("Router" in dtype or "Switch" in dtype) else 15
            }
            nodes.append(node)

        links = _topology_links(devices)

        return {"nodes": nodes, "links": links}
    except Exception as e:
        logger.error(f"Error fetching topology data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch topology data")

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
