import streamlit as st
import streamlit.components.v1 as components
import requests
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import time
import os
import base64
import re

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AI Network Copilot",
    page_icon="🛸",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_BASE_URL = "http://localhost:8000"

# ─────────────────────────────────────────────
#  SESSION STATE
# ─────────────────────────────────────────────
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 300  # 5 minutes default
if "data_limit" not in st.session_state:
    st.session_state.data_limit = 100
if "ping_result" not in st.session_state:
    st.session_state.ping_result = None
if "pinging" not in st.session_state:
    st.session_state.pinging = False

# ─────────────────────────────────────────────
#  DATA FETCHING FUNCTIONS
# ─────────────────────────────────────────────
_TS_CANDIDATES = ["ts", "timestamp", "time", "datetime", "created_at", "recorded_at"]

def _unwrap(data, fallback_keys=("metrics", "alerts", "hosts", "data", "results", "items")):
    """If the API returns a dict wrapper like {'metrics': [...]}, unwrap the list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in fallback_keys:
            if key in data and isinstance(data[key], list):
                return data[key]
        for v in data.values():
            if isinstance(v, list):
                return v
    return []

def fetch_metrics(limit=100, force_http=False):
    # Use WebSocket cache only for small quick fetches, not for complete views
    if not force_http and (st.session_state.get('latest_metrics') and
        len(st.session_state.latest_metrics) > 0):
        return st.session_state.latest_metrics[:limit]

    # Fallback to HTTP polling
    try:
        resp = requests.get(f"{API_BASE_URL}/metrics/latest?limit={limit}", timeout=5)
        resp.raise_for_status()
        return _unwrap(resp.json())
    except Exception as e:
        st.error(f"Failed to fetch metrics: {e}")
        return []

def fetch_alerts(limit=50):
    # Check if we have recent WebSocket data first
    if (st.session_state.get('latest_alerts') and
        len(st.session_state.latest_alerts) > 0):
        # Return cached WebSocket data
        return st.session_state.latest_alerts[:limit]

    # Fallback to HTTP polling
    try:
        resp = requests.get(f"{API_BASE_URL}/alerts?limit={limit}", timeout=5)
        resp.raise_for_status()
        return _unwrap(resp.json())
    except Exception as e:
        st.error(f"Failed to fetch alerts: {e}")
        return []

def fetch_hosts():
    try:
        resp = requests.get(f"{API_BASE_URL}/hosts", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return _unwrap(data) if isinstance(data, dict) else data
    except Exception as e:
        st.error(f"Failed to fetch hosts: {e}")
        return []

def fetch_hosts_detail():
    try:
        resp = requests.get(f"{API_BASE_URL}/hosts/detail", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return _unwrap(data) if isinstance(data, dict) else data
    except Exception as e:
        st.error(f"Failed to fetch host details: {e}")
        return []

def fetch_devices():
    try:
        resp = requests.get(f"{API_BASE_URL}/devices", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return _unwrap(data) if isinstance(data, dict) else data
    except Exception as e:
        st.error(f"Failed to fetch device information: {e}")
        return []

def fetch_topology():
    # Check if we have recent WebSocket data first
    if (st.session_state.get('latest_topology') and
        st.session_state.latest_topology.get('nodes')):
        return st.session_state.latest_topology
    # Fallback to HTTP polling — return None on any error
    try:
        resp = requests.get(f"{API_BASE_URL}/topology", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        # Unwrap if needed
        if isinstance(data, dict) and ("nodes" in data or "links" in data):
            return data
        return None
    except Exception:
        return None

def ping_host(host):
    """Ping a single host via the API."""
    try:
        resp = requests.get(f"{API_BASE_URL}/ping/{host}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"Ping failed: {e}")
        return None

# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.header("Settings")
    refresh_interval = st.slider(
        "Refresh interval (seconds)",
        min_value=5,
        max_value=3600,  # 1 hour max
        value=st.session_state.refresh_interval,
        step=5,  # Step in 5-second intervals for smoother control
    )
    if refresh_interval != st.session_state.refresh_interval:
        st.session_state.refresh_interval = refresh_interval

    data_limit = st.slider(
        "Data points to fetch",
        min_value=10,
        max_value=200,
        value=st.session_state.data_limit,
        step=10,
    )
    if data_limit != st.session_state.data_limit:
        st.session_state.data_limit = data_limit

    st.divider()
    st.subheader("Manual Ping Test")
    ping_host_input = st.text_input(
        "Host to ping",
        value="8.8.8.8",
        help="Enter a hostname or IP address to ping",
    )
    if st.button("Ping Host", type="primary"):
        st.session_state.pinging = True
        st.session_state.ping_result = None
        with st.spinner(f"Pinging {ping_host_input}..."):
            result = ping_host(ping_host_input)
            st.session_state.ping_result = result
            st.session_state.pinging = False
        # Rerun to update the UI with the result
        st.rerun()

    # Display ping result if available
    if st.session_state.ping_result:
        result = st.session_state.ping_result
        latency = result.get("latency")
        is_anomaly = result.get("is_anomaly", False)
        ts = result.get("ts")
        if latency is not None:
            st.success(f"✅ {ping_host_input}: {latency:.2f} ms")
        else:
            st.error(f"❌ {ping_host_input}: Ping failed")
        if ts:
            try:
                ts_dt = datetime.fromisoformat(ts)
                st.caption(f"Time: {ts_dt.strftime('%H:%M:%S')}")
            except:
                pass

    # ─────────────────────────────────────────────
    #  AUTO-REFRESH
    # ─────────────────────────────────────────────
if HAS_AUTOREFRESH:
    count = st_autorefresh(
        interval=st.session_state.refresh_interval * 1000,
        key="datarefresh",
    )
else:
    st.warning("Auto-refresh not available. Install streamlit-autorefresh for live updates.")

# ─────────────────────────────────────────────
#  WEBSOCKET CONNECTIONS FOR REAL-TIME UPDATES (SUPPLEMENTAL)
# ─────────────────────────────────────────────
# Initialize WebSocket connection states in session state
if "ws_connected" not in st.session_state:
    st.session_state.ws_connected = False
if "ws_messages" not in st.session_state:
    st.session_state.ws_messages = []
if "latest_metrics" not in st.session_state:
    st.session_state.latest_metrics = []
if "latest_alerts" not in st.session_state:
    st.session_state.latest_alerts = []
if "latest_topology" not in st.session_state:
    st.session_state.latest_topology = {"nodes": [], "links": []}
# Initialize WebSocket connection status for each type
if "ws_metrics_connected" not in st.session_state:
    st.session_state.ws_metrics_connected = False
if "ws_alerts_connected" not in st.session_state:
    st.session_state.ws_alerts_connected = False
if "ws_topology_connected" not in st.session_state:
    st.session_state.ws_topology_connected = False
if "last_processed_message" not in st.session_state:
    st.session_state.last_processed_message = ""
if "ws_placeholder" not in st.session_state:
    st.session_state.ws_placeholder = st.sidebar.empty()

# JavaScript for WebSocket connections
websocket_js = """
<script>
// WebSocket connections
let wsConnections = {};

// Initialize WebSocket connections
function initWebSockets() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname;
    const port = window.location.port ? `:${window.location.port}` : '';
    const baseUrl = `${protocol}//${host}${port}`;

    // Connect to metrics WebSocket
    wsConnections.metrics = new WebSocket(`${baseUrl}/ws/metrics`);
    wsConnections.messages = new WebSocket(`${baseUrl}/ws/alerts`);
    wsConnections.topology = new WebSocket(`${baseUrl}/ws/topology`);

    // Handle messages from all WebSocket connections
    Object.keys(wsConnections).forEach(type => {
        wsConnections[type].onopen = () => {
            console.log(`Connected to ${type} WebSocket`);
            // Update the Streamlit text input to signal connection
            updateStreamlitField({
                wsType: 'status',
                data: { connected: true, type: type, timestamp: Date.now() }
            });
        };

        wsConnections[type].onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                // Send message to Streamlit via our custom input
                updateStreamlitField({
                    wsType: type,
                    data: data,
                    timestamp: Date.now()
                });
            } catch (e) {
                console.error('Error parsing WebSocket message:', e);
            }
        };

        wsConnections[type].onclose = () => {
            console.log(`Disconnected from ${type} WebSocket`);
            // Update the Streamlit text input to signal disconnection
            updateStreamlitField({
                wsType: 'status',
                data: { connected: false, type: type, timestamp: Date.now() }
            });
        };

        wsConnections[type].onerror = (error) => {
            console.error(`WebSocket error for ${type}:`, error);
            // Update the Streamlit text input to signal error
            updateStreamlitField({
                wsType: 'status',
                data: { connected: false, type: type, error: error.message, timestamp: Date.now() }
            });
        };
    });
}

// Helper function to update the Streamlit hidden input field
function updateStreamlitField(data) {
    try {
        // Find the Streamlit text input element by its label or test ID
        // Streamlit generates predictable IDs for elements
        const inputs = document.querySelectorAll('input[type="text"]');
        let targetInput = null;

        // Look for our specific input by checking nearby labels or attributes
        inputs.forEach(input => {
            // The input we created has label_visibility="collapsed"
            // We'll look for an input that's likely to be our hidden one
            if (input.offsetParent === null ||
                (input.offsetWidth === 0 && input.offsetHeight === 0)) {
                // This is likely a hidden element
                targetInput = input;
            }
        });

        // If we couldn't find it by visibility, try to find it by proximity to our label
        if (!targetInput) {
            const labels = document.querySelectorAll('label');
            labels.forEach(label => {
                if (label.textContent.includes('WebSocket Messages Receiver')) {
                    // Find the input associated with this label
                    const inputId = label.getAttribute('for');
                    if (inputId) {
                        targetInput = document.getElementById(inputId);
                    }
                }
            });
        }

        // If we found the input, update its value and trigger an event
        if (targetInput) {
            const jsonData = JSON.stringify(data);
            targetInput.value = jsonData;
            // Trigger an input event to notify Streamlit of the change
            targetInput.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
            // Fallback: store in localStorage and periodically check
            localStorage.setItem('streamlit_ws_message', JSON.stringify(data));
        }
    } catch (e) {
        console.error('Error updating Streamlit field:', e);
    }
}

// Initialize WebSockets when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWebSockets);
} else {
    initWebSockets();
}
</script>
"""

# Add the WebSocket JavaScript to the Streamlit app
st.components.v1.html(websocket_js, height=0)

# Hidden component to receive WebSocket messages from JavaScript
# We use a text area that gets updated by JS and triggers Streamlit reruns
websocket_receiver = st.text_input(
    "WebSocket Messages Receiver",
    value="",
    label_visibility="collapsed",
    key="websocket_msg_receiver",
    help="Hidden field to receive WebSocket messages"
)

# Process WebSocket messages when the receiver changes
if websocket_receiver and websocket_receiver != "":
    try:
        message_data = json.loads(websocket_receiver)
        ws_type = message_data.get("wsType")
        data = message_data.get("data")

        if ws_type == "metrics" and isinstance(data, dict) and "data" in data:
            # Update metrics data
            st.session_state.latest_metrics = data["data"]
            st.session_state.ws_metrics_connected = True
        elif ws_type == "alerts" and isinstance(data, dict) and "data" in data:
            # Update alerts data
            st.session_state.latest_alerts = data["data"]
            st.session_state.ws_alerts_connected = True
        elif ws_type == "topology" and isinstance(data, dict) and "data" in data:
            # Update topology data
            st.session_state.latest_topology = data["data"]
            st.session_state.ws_topology_connected = True
        elif ws_type == "status":
            # Update connection status for specific type
            connected = data.get("connected", False)
            ws_type_specific = data.get("type")
            if ws_type_specific == "metrics":
                st.session_state.ws_metrics_connected = connected
            elif ws_type_specific == "alerts":
                st.session_state.ws_alerts_connected = connected
            elif ws_type_specific == "topology":
                st.session_state.ws_topology_connected = connected

        # Update overall connection status
        metrics_conn = st.session_state.get('ws_metrics_connected', False)
        alerts_conn = st.session_state.get('ws_alerts_connected', False)
        topology_conn = st.session_state.get('ws_topology_connected', False)
        st.session_state.ws_connected = metrics_conn or alerts_conn or topology_conn

        # Clear the receiver after processing by setting it to empty string
        # We need to do this through the text_input widget, but we can't
        # directly modify it here. Instead, we'll rely on the fact that
        # Streamlit will rerun and we'll process the message once.
        # To prevent reprocessing, we'll clear it on the next cycle by
        # setting a flag
        st.session_state.last_processed_message = websocket_receiver

    except json.JSONDecodeError:
        # Invalid JSON, ignore
        pass
    except Exception as e:
        # Other error, log it but don't crash
        pass

# Processed WebSocket message marker to prevent reprocessing
if websocket_receiver and websocket_receiver != "" and websocket_receiver != st.session_state.last_processed_message:
    try:
        message_data = json.loads(websocket_receiver)
        ws_type = message_data.get("wsType")
        data = message_data.get("data")

        if ws_type == "metrics" and isinstance(data, dict) and "data" in data:
            # Update metrics data
            st.session_state.latest_metrics = data["data"]
            st.session_state.ws_metrics_connected = True
        elif ws_type == "alerts" and isinstance(data, dict) and "data" in data:
            # Update alerts data
            st.session_state.latest_alerts = data["data"]
            st.session_state.ws_alerts_connected = True
        elif ws_type == "topology" and isinstance(data, dict) and "data" in data:
            # Update topology data
            st.session_state.latest_topology = data["data"]
            st.session_state.ws_topology_connected = True
        elif ws_type == "status":
            # Update connection status for specific type
            connected = data.get("connected", False)
            ws_type_specific = data.get("type")
            if ws_type_specific == "metrics":
                st.session_state.ws_metrics_connected = connected
            elif ws_type_specific == "alerts":
                st.session_state.ws_alerts_connected = connected
            elif ws_type_specific == "topology":
                st.session_state.ws_topology_connected = connected

        # Update overall connection status
        metrics_conn = st.session_state.get('ws_metrics_connected', False)
        alerts_conn = st.session_state.get('ws_alerts_connected', False)
        topology_conn = st.session_state.get('ws_topology_connected', False)
        st.session_state.ws_connected = metrics_conn or alerts_conn or topology_conn

        # Mark this message as processed
        st.session_state.last_processed_message = websocket_receiver

    except json.JSONDecodeError:
        # Invalid JSON, ignore
        pass
    except Exception as e:
        # Other error, log it but don't crash
        pass

# Function to update WebSocket status in sidebar
def update_ws_status():
    # Count connected WebSocket types
    connected_types = []
    if st.session_state.get('ws_metrics_connected', False):
        connected_types.append("Metrics")
    if st.session_state.get('ws_alerts_connected', False):
        connected_types.append("Alerts")
    if st.session_state.get('ws_topology_connected', False):
        connected_types.append("Topology")

    if connected_types:
        status_text = f"🟢 Connected: {', '.join(connected_types)}"
    else:
        status_text = "🔴 Disconnected"

    # Update the placeholder if it exists
    if 'ws_placeholder' in st.session_state:
        st.session_state.ws_placeholder.markdown(f"**WebSocket Status:** {status_text}")

# Update WebSocket status display in sidebar
update_ws_status()

# ─────────────────────────────────────────────
#  CSS — Black & Violet + Space Background
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;600&display=swap');

/* ── Kill every Streamlit background layer ── */
html, body {
    background: #08070f !important;
    margin: 0; padding: 0;
}
.stApp,
[data-testid="stAppViewContainer"],
[data-testid="stHeader"],
[data-testid="stToolbar"],
.main,
section.main,
[data-testid="stAppViewBlockContainer"],
[data-testid="stMain"],
[data-testid="stMainBlockContainer"],
[data-testid="stVerticalBlock"],
.element-container,
div[class^="block-"] {
    background: transparent !important;
}
.block-container {
    background: transparent !important;
    padding: 3.2rem 2rem 2rem 2rem !important;
    max-width: 100% !important;
    position: relative;
    z-index: 2;
}

/* ── Black hole video fixed behind everything ── */
#bh-video-bg {
    position: fixed !important;
    top: 0 !important; left: 0 !important;
    width: 100vw !important; height: 100vh !important;
    object-fit: cover !important;
    z-index: 0 !important;
    pointer-events: none !important;
    display: block !important;
}
#bh-video-scrim {
    position: fixed !important;
    top: 0 !important; left: 0 !important;
    width: 100vw !important; height: 100vh !important;
    z-index: 1 !important;
    pointer-events: none !important;
    display: block !important;
}

/* ── Color & font base ── */
html, body, [class*="css"] {
    color: #E0D7FF !important;
    font-family: 'Inter', sans-serif;
}
#MainMenu, footer, header { visibility: hidden; }

/* ── Hide the invisible WebSocket receiver widget (data channel only,
     label_visibility="collapsed" still renders the empty input box) ── */
div[data-testid="stTextInput"]:has(input[aria-label="WebSocket Messages Receiver"]) {
    display: none !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}

/* ── Live status pill (minimal, floating, replaces old hero banner) ── */
.status-mini {
    position: fixed; top: 0.9rem; right: 1.4rem; z-index: 3;
    display: flex; align-items: center; gap: 0.5rem;
    background: rgba(20,0,45,0.55);
    border: 1px solid rgba(123,0,255,0.35);
    border-radius: 999px;
    padding: 0.35rem 0.85rem;
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.68rem; letter-spacing: 0.1em;
}
.dot-pulse {
    width: 7px; height: 7px; border-radius: 50%;
    animation: dot-blink 1.4s ease-in-out infinite;
}
@keyframes dot-blink {
    0%,100% { opacity:1; box-shadow: 0 0 0 0 currentColor; }
    50%      { opacity:0.6; box-shadow: 0 0 0 5px transparent; }
}

/* ── KPI Cards ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.4rem;
}
.kpi-card {
    background: rgba(20,0,45,0.6);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    position: relative; overflow: hidden;
    backdrop-filter: blur(10px);
    transition: transform 0.25s, box-shadow 0.25s;
    cursor: default;
}
.kpi-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 32px rgba(123,0,255,0.25);
}
.kpi-card::before {
    content: '';
    position: absolute; inset: 0;
    border-radius: 12px;
    padding: 1px;
    background: linear-gradient(135deg, var(--accent), transparent 60%);
    -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
    -webkit-mask-composite: xor;
    mask-composite: exclude;
}
.kpi-card.c1 { --accent: #BF5FFF; }
.kpi-card.c2 { --accent: #7B00FF; }
.kpi-card.c3 { --accent: #9D4EDD; }
.kpi-card.c4 { --accent: #FF4DFF; }
.kpi-label {
    font-size: 0.65rem; letter-spacing: 0.2em;
    text-transform: uppercase; color: rgba(191,95,255,0.6);
    margin-bottom: 0.5rem;
    font-family: 'Share Tech Mono', monospace;
}
.kpi-value {
    font-family: 'Orbitron', sans-serif;
    font-size: 1.9rem; font-weight: 700;
    line-height: 1; margin-bottom: 0.25rem;
    color: #FFFFFF;
    text-shadow: 0 0 20px var(--accent);
}
.kpi-unit {
    font-size: 0.7rem; color: rgba(224,215,255,0.4);
    font-family: 'Share Tech Mono', monospace;
}
.kpi-card::after {
    content: '';
    position: absolute; top: 0; left: -100%;
    width: 60%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(191,95,255,0.06), transparent);
    animation: shimmer 4s ease-in-out infinite;
    animation-delay: var(--delay, 0s);
}
.kpi-card.c1 { --delay: 0s; }
.kpi-card.c2 { --delay: 0.8s; }
.kpi-card.c3 { --delay: 1.6s; }
.kpi-card.c4 { --delay: 2.4s; }
@keyframes shimmer { 0%,100%{left:-100%} 50%{left:100%} }

/* ── Section headers ── */
.sec-head {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.68rem; letter-spacing: 0.22em;
    text-transform: uppercase; color: #BF5FFF;
    border-bottom: 1px solid rgba(123,0,255,0.3);
    padding-bottom: 0.45rem; margin: 1.4rem 0 1rem 0;
}

/* ── Alerts (readable glass panel over the video) ── */

/* Severity cards — Linear.app-style hover glow, click = filter */
.sev-cards-row {
    display: flex; gap: 0.9rem; margin-bottom: 1.2rem; flex-wrap: wrap;
}
.sev-card {
    background: rgba(20,0,45,0.5);
    border: 1px solid rgba(123,0,255,0.4);
    border-radius: 14px;
    cursor: pointer;
    position: relative;
    overflow: hidden;
    height: 148px;
    flex: 1 1 0;
    min-width: 200px;
    padding: 1rem 1.1rem;
    display: flex; flex-direction: column; justify-content: flex-end;
    transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease;
}
.sev-card:hover { transform: translateY(-3px); border-color: rgba(191,95,255,0.6); }
.sev-card.active {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent), 0 14px 34px -12px var(--accent);
}
.sev-card::before, .sev-card::after {
    content: ''; position: absolute; inset: 0; border-radius: inherit;
    opacity: 0; transition: opacity .4s ease; pointer-events: none;
}
.sev-card::before {
    background: radial-gradient(480px circle at var(--mx,50%) var(--my,50%), rgba(255,255,255,0.09), transparent 42%);
    z-index: 2;
}
.sev-card::after {
    background: radial-gradient(380px circle at var(--mx,50%) var(--my,50%), var(--glow, rgba(191,95,255,0.35)), transparent 45%);
    z-index: 1;
}
.sev-card:hover::before, .sev-card:hover::after { opacity: 1; }
.sev-card-icon {
    position: absolute; top: 0.3rem; right: 0.6rem;
    font-size: 3.8em; opacity: 0.3; line-height: 1;
    color: var(--accent, #BF5FFF); z-index: 0;
}
.sev-card-count {
    font-family: 'Orbitron', sans-serif; font-size: 2rem; font-weight: 700;
    color: #fff; position: relative; z-index: 3; line-height: 1;
}
.sev-card-title {
    font-family: 'Share Tech Mono', monospace; font-size: 0.78rem; letter-spacing: 0.04em;
    text-transform: none; color: #FFFFFF;
    margin-top: 0.4rem; position: relative; z-index: 3;
    line-height: 1.4;
    display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
    overflow: hidden;
}
.sev-card-sub {
    font-size: 0.72rem; color: rgba(255,255,255,0.45);
    margin-top: 0.2rem; position: relative; z-index: 3;
}

/* Real (invisible) Streamlit button pulled up to sit exactly over its card.
   Scoped to the element-container level (both old/new Streamlit DOM naming)
   so it can't accidentally match at the column level and shove a whole
   neighboring column upward. Uses the generic .sev-card marker since cards
   are generated dynamically (one per distinct alert reason), not a fixed set. */
div[data-testid="stElementContainer"]:has(.sev-card) + div[data-testid="stElementContainer"] button,
div.element-container:has(.sev-card) + div.element-container button {
    background: transparent !important; border: none !important; color: transparent !important;
    box-shadow: none !important; width: 100% !important; height: 148px !important; cursor: pointer;
}
div[data-testid="stElementContainer"]:has(.sev-card) + div[data-testid="stElementContainer"],
div.element-container:has(.sev-card) + div.element-container {
    margin-top: -148px !important; position: relative; z-index: 5;
}

.reset-filter-marker { height: 0; }
div[data-testid="stElementContainer"]:has(.reset-filter-marker) + div[data-testid="stElementContainer"] button,
div.element-container:has(.reset-filter-marker) + div.element-container button {
    background: rgba(20,8,40,0.5) !important;
    border: 1px solid rgba(123,0,255,0.3) !important;
    color: rgba(224,215,255,0.75) !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    border-radius: 999px !important;
    padding: 0.25rem 0.9rem !important;
}

/* Slide-down reveal when a card is clicked / the active filter changes */
@keyframes slide-down-reveal {
    0%   { clip-path: inset(0 0 100% 0); opacity: 0.25; transform: translateY(-14px); }
    100% { clip-path: inset(0 0 0 0);    opacity: 1;    transform: translateY(0); }
}
.sev-panel-wrap.swipe { animation: slide-down-reveal 0.5s cubic-bezier(.2,.8,.2,1); transform-origin: top; }

/* Group header per severity */
.sev-group-head {
    display: flex; justify-content: space-between; align-items: center;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem; letter-spacing: 0.14em; text-transform: uppercase;
    margin: 1.3rem 0 0.5rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid rgba(123,0,255,0.22);
}
.sev-group-head:first-of-type { margin-top: 0; }
.sev-count {
    background: rgba(123,0,255,0.16);
    padding: 0.12rem 0.55rem;
    border-radius: 999px;
    font-size: 0.66rem;
    color: #E0D7FF;
}
.alert-more {
    text-align: center; font-size: 0.7rem; color: rgba(191,95,255,0.45);
    font-family: 'Share Tech Mono', monospace; margin: 0.5rem 0 0.2rem;
}

.alert-panel {
    background: rgba(9,3,20,0.82);
    border: 1px solid rgba(123,0,255,0.3);
    border-radius: 12px;
    backdrop-filter: blur(18px) saturate(150%);
    -webkit-backdrop-filter: blur(18px) saturate(150%);
    box-shadow: 0 10px 34px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.05);
    padding: 0.3rem 0.7rem;
    overflow: hidden;
}
.alert-row {
    display: flex; align-items: center; gap: 0.9rem;
    padding: 0.72rem 0.5rem 0.72rem 0.7rem;
    border-bottom: 1px solid rgba(123,0,255,0.14);
    border-left: 3px solid var(--accent, transparent);
    animation: slide-in 0.35s ease;
}
.alert-row:last-child { border-bottom: none; }
.alert-row:hover { background: rgba(123,0,255,0.09); }
@keyframes slide-in { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:none} }
.a-icon {
    width: 26px; height: 26px; flex-shrink: 0;
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.78rem; line-height: 1;
}
.a-host   { font-family: 'Share Tech Mono', monospace; color: #FFFFFF; font-weight: 700; font-size: 0.83rem; min-width: 108px; }
.a-reason { color: #E9E1FF; font-size: 0.83rem; flex: 1; }
.a-time   { color: rgba(191,95,255,0.6); font-size: 0.72rem; font-family: 'Share Tech Mono', monospace; white-space: nowrap; }

/* ── Host table ── */
.htable { width:100%; border-collapse:collapse; }
.htable th {
    font-family:'Share Tech Mono',monospace; font-size:0.65rem;
    letter-spacing:0.15em; text-transform:uppercase;
    color:rgba(191,95,255,0.55); border-bottom:1px solid rgba(123,0,255,0.3);
    padding:0.5rem 0.7rem; text-align:left;
}
.htable td {
    font-size:0.82rem; color:#E0D7FF;
    border-bottom:1px solid rgba(123,0,255,0.1);
    padding:0.55rem 0.7rem;
}
.htable tr:hover td { background:rgba(123,0,255,0.06); }
.badge-ok   { background:rgba(0,255,136,0.08); color:#00FF88; border:1px solid rgba(0,255,136,0.25); border-radius:4px; padding:1px 8px; font-size:0.65rem; font-family:'Share Tech Mono',monospace; }
.badge-warn { background:rgba(255,77,255,0.08); color:#FF4DFF; border:1px solid rgba(255,77,255,0.25); border-radius:4px; padding:1px 8px; font-size:0.65rem; font-family:'Share Tech Mono',monospace; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: rgba(10,0,25,0.95) !important;
    border-right: 1px solid rgba(123,0,255,0.25) !important;
}
section[data-testid="stSidebar"] * { color: #E0D7FF !important; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: transparent;
    border-bottom: 1px solid rgba(123,0,255,0.3); gap: 0;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important; border: none !important;
    color: rgba(191,95,255,0.5) !important;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem; letter-spacing: 0.12em;
    text-transform: uppercase; padding: 0.6rem 1.2rem;
}
.stTabs [aria-selected="true"] {
    color: #BF5FFF !important;
    border-bottom: 2px solid #BF5FFF !important;
    background: transparent !important;
}

/* ── Refresh progress ── */
.prog-wrap { background:rgba(20,0,45,0.6); border:1px solid rgba(123,0,255,0.25); border-radius:8px; padding:0.7rem 1rem; margin-bottom:1rem; backdrop-filter:blur(8px); }
.prog-label { font-size:0.65rem; color:rgba(191,95,255,0.55); letter-spacing:0.12em; text-transform:uppercase; margin-bottom:0.35rem; font-family:'Share Tech Mono',monospace; }
.prog-track { background:rgba(123,0,255,0.15); border-radius:3px; height:3px; }
.prog-fill  { background:linear-gradient(90deg,#7B00FF,#BF5FFF,#FF4DFF); border-radius:3px; height:3px; transition:width 1s linear; }

/* ── No-data box ── */
.no-data {
    background:rgba(60,0,120,0.2); border:1px solid rgba(191,95,255,0.25);
    border-radius:12px; padding:3rem; text-align:center; margin-top:2rem;
}

/* ── Footer ── */
.foot {
    text-align:center; padding:1.2rem 0 0.4rem;
    font-family:'Share Tech Mono',monospace; font-size:0.62rem;
    color:rgba(123,0,255,0.4); letter-spacing:0.15em; text-transform:uppercase;
    border-top:1px solid rgba(123,0,255,0.2); margin-top:2rem;
}

/* ── Boot / loading overlay ── */
.boot-overlay {
    position: fixed; inset: 0; z-index: 9999;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 1.15rem;
    background: rgba(5,3,12,0.9);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    animation: boot-fade-in 0.4s ease;
}
@keyframes boot-fade-in { from{opacity:0;} to{opacity:1;} }
.boot-icon-wrap {
    position: relative;
    width: 104px; height: 104px;
    display: flex; align-items: center; justify-content: center;
}
.boot-icon {
    width: 60px; height: 60px;
    animation: boot-float 2.4s ease-in-out infinite;
    filter: drop-shadow(0 0 18px rgba(123,0,255,0.6));
}
@keyframes boot-float {
    0%,100% { transform: translateY(0); }
    50%     { transform: translateY(-10px); }
}
.boot-ring {
    position: absolute; inset: 0;
    border-radius: 50%;
    border: 2px solid rgba(123,0,255,0.15);
    border-top-color: #BF5FFF;
    border-right-color: rgba(191,95,255,0.35);
    animation: boot-spin 1.3s linear infinite;
}
@keyframes boot-spin { to { transform: rotate(360deg); } }
.boot-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.76rem; letter-spacing: 0.24em; text-transform: uppercase;
    color: #BF5FFF;
    text-shadow: 0 0 12px rgba(191,95,255,0.5);
}
.boot-dots span {
    display: inline-block; width: 5px; height: 5px; border-radius: 50%;
    background: #BF5FFF; margin: 0 3px;
    animation: boot-dot-blink 1.2s ease-in-out infinite;
}
.boot-dots span:nth-child(2) { animation-delay: 0.2s; }
.boot-dots span:nth-child(3) { animation-delay: 0.4s; }
@keyframes boot-dot-blink { 0%,80%,100%{opacity:0.2;} 40%{opacity:1;} }

/* ── Shooting star — plays across the screen on tab switch ── */
.shooting-star {
    position: fixed;
    top: 0; left: 0;
    z-index: 9998;
    pointer-events: none;
    width: 0; height: 0;
    animation: shoot-across var(--dur, 1.05s) cubic-bezier(.25,.6,.35,1) forwards;
}
.shooting-star .head {
    position: absolute;
    width: var(--size, 14px); height: var(--size, 14px);
    border-radius: 50%;
    background: radial-gradient(circle, #ffffff 0%, #E7D2FF 30%, var(--tint, #BF5FFF) 62%, transparent 82%);
    box-shadow:
        0 0 18px 6px rgba(191,95,255,0.85),
        0 0 40px 16px rgba(123,0,255,0.5),
        0 0 70px 28px rgba(123,0,255,0.22);
    transform: translate(-50%, -50%);
}
.shooting-star .trail {
    position: absolute;
    right: 50%; top: 50%;
    width: var(--trail, 340px); height: 4px;
    transform: translateY(-50%);
    background: linear-gradient(90deg,
        transparent 0%,
        rgba(123,0,255,0.15) 20%,
        rgba(191,95,255,0.55) 55%,
        rgba(255,255,255,0.95) 100%);
    border-radius: 999px;
    filter: blur(0.4px);
}
.shooting-star .spark {
    position: absolute;
    width: 4px; height: 4px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 0 8px 2px rgba(255,255,255,0.9);
    animation: spark-twinkle 0.5s ease-in-out infinite;
}
@keyframes spark-twinkle { 0%,100%{opacity:0.2;transform:scale(0.6);} 50%{opacity:1;transform:scale(1.2);} }
@keyframes shoot-across {
    0%   { transform: translate(var(--sx), var(--sy)) rotate(var(--ang)) scale(0.4); opacity: 0; }
    10%  { opacity: 1; transform: translate(var(--sx), var(--sy)) rotate(var(--ang)) scale(1); }
    82%  { opacity: 1; }
    100% { transform: translate(var(--ex), var(--ey)) rotate(var(--ang)) scale(1); opacity: 0; }
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  BOOT / LOADING OVERLAY — floating app icon,
#  shown once per session until the first data fetch completes.
# ─────────────────────────────────────────────
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_boot_ph = st.empty()

# Show boot overlay until actual data arrives (first simulator cycle)
def _should_hide_boot(metrics, devices):
    return bool(metrics) and bool(devices)

_show_boot = not st.session_state.get("boot_done", False)

if _show_boot:
    @st.cache_resource(show_spinner=False)
    def _load_icon_b64():
        icon_path = os.path.join(_STATIC_DIR, "app-icon.png")
        with open(icon_path, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

    _icon_b64 = _load_icon_b64()
    _boot_ph.markdown(f"""
    <div class='boot-overlay' id='boot-overlay'>
      <div class='boot-icon-wrap'>
        <img class='boot-icon' src='data:image/png;base64,{_icon_b64}'/>
        <div class='boot-ring'></div>
      </div>
      <div class='boot-text' id='boot-text'>Waiting for first network scan...</div>
      <div class='boot-dots'><span></span><span></span><span></span></div>
    </div>
    """, unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  VIDEO BACKGROUND — real black hole footage
#  Served by a tiny local HTTP thread (not base64-embedded),
#  so the browser streams it directly with zero impact on the
#  Streamlit websocket or the FastAPI metrics API.
# ─────────────────────────────────────────────

@st.cache_resource(show_spinner=False)
def _start_static_server():
    import http.server
    import socketserver
    import threading

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=_STATIC_DIR, **kwargs)
        def log_message(self, *args, **kwargs):
            pass  # keep the terminal clean

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), QuietHandler)
    httpd.daemon_threads = True
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port

_static_port = _start_static_server()
_video_url = f"http://127.0.0.1:{_static_port}/black-hole-sun-moewalls-com.mp4"

# ── Manual device-type overrides by IP (edit to tag your devices) ─
_DEVICE_TYPE_OVERRIDES = {
    "192.168.1.15": "Smart TV",
    "192.168.1.14": "Intel PC",
}

# ── Icon mapping for topology nodes ──────────────────────────────
_DEVICE_ICON_FILES = {
    "router":   "router.png",
    "switch":   "switch.png",
    "server":   "server.png",
    "phone":    "phone.png",
    "mobile":   "phone.png",
    "android tv": "tv.png",
    "tv":       "tv.png",
    "linux":    "linux-client.png",
    "mac":      "mac-client.png",
    "windows":  "windows-client.png",
    "pc":       "windows-client.png",
    "workstation": "windows-client.png",
    "host":     "windows-client.png",
    "cloud":    "cloud.png",
}

@st.cache_resource(show_spinner=False)
def _get_icon_data_uri(dtype, hostname=None):
    if not dtype:
        return None
    dt_lower = dtype.lower()
    # Hostname-based override — if hostname hints at TV, use tv icon
    h = (hostname or "").lower()
    if "tv" in h or "tele" in h or "smarttv" in h:
        for key, filename in _DEVICE_ICON_FILES.items():
            if key in ("tv", "android tv"):
                path = os.path.join(_STATIC_DIR, filename)
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        return "data:image/png;base64," + base64.b64encode(f.read()).decode()
    for key, filename in _DEVICE_ICON_FILES.items():
        if key in dt_lower:
            path = os.path.join(_STATIC_DIR, filename)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    return "data:image/png;base64," + base64.b64encode(f.read()).decode()
    return None

if not st.session_state.get("bg_video_injected", False):
    components.html(f"""
    <script>
    (function(){{
      const doc  = window.parent.document;
      const body = doc.body;

      if (!doc.getElementById('gf-orbitron')) {{
        const lk = doc.createElement('link');
        lk.id   = 'gf-orbitron';
        lk.rel  = 'stylesheet';
        lk.href = 'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&family=Inter:wght@300;400;600&display=swap';
        doc.head.appendChild(lk);
      }}

      body.style.background = '#08070f';

      if (doc.getElementById('bh-video-bg')) return;

      const scrim = doc.createElement('div');
      scrim.id = 'bh-video-scrim';
      scrim.style.background =
        'radial-gradient(ellipse 70% 55% at 50% 42%, rgba(8,7,15,0.12) 0%, rgba(8,7,15,0.68) 58%, rgba(8,7,15,0.92) 100%)';
      body.prepend(scrim);

      const video = doc.createElement('video');
      video.id = 'bh-video-bg';
      video.src = '{_video_url}';
      video.autoplay = true;
      video.muted = true;
      video.loop = true;
      video.playsInline = true;
      body.prepend(video);
    }})();
    </script>
    """, height=0)
    st.session_state.bg_video_injected = True

# ─────────────────────────────────────────────
#  SHOOTING STAR — plays whenever a tab is switched
#  Re-injected on every rerun (cheap, height=0) instead of gated to
#  "once per session": st.rerun() calls elsewhere (e.g. the alert cards)
#  tear down this iframe, and a browser kills any listener the iframe
#  attached to the parent document when it goes. Re-injecting every run
#  and cleanly swapping the handler (rather than trusting a permanent
#  "already bound" flag) keeps a live listener at all times.
# ─────────────────────────────────────────────
components.html("""
<script>
(function(){
  const doc = window.parent.document;

  // Replace any previous handler (possibly orphaned by a torn-down iframe)
  // instead of skipping based on a flag that would survive that teardown.
  if (doc.__starHandler) {
    doc.removeEventListener('click', doc.__starHandler, true);
  }

  const TINTS = ['#BF5FFF', '#7B00FF', '#E0AEFF', '#9B6BFF'];

  function spawnStar(delay, big){
    setTimeout(function(){
      const W = window.parent.innerWidth;
      const H = window.parent.innerHeight;

      const angle   = 18 + Math.random()*16;           // shallow diagonal
      const rad     = angle * Math.PI / 180;
      const startX  = -80 - Math.random()*160;
      const startY  = Math.random()*H*0.55;
      const dist    = W + 260;
      const endX    = startX + Math.cos(rad)*dist;
      const endY    = startY + Math.sin(rad)*dist;

      const size  = big ? (20 + Math.random()*8) : (12 + Math.random()*6);
      const trail = big ? (420 + Math.random()*120) : (260 + Math.random()*80);
      const dur   = big ? (1.0 + Math.random()*0.2) : (0.8 + Math.random()*0.2);
      const tint  = TINTS[Math.floor(Math.random()*TINTS.length)];

      const star = doc.createElement('div');
      star.className = 'shooting-star';
      star.style.setProperty('--sx', startX+'px');
      star.style.setProperty('--sy', startY+'px');
      star.style.setProperty('--ex', endX+'px');
      star.style.setProperty('--ey', endY+'px');
      star.style.setProperty('--ang', angle+'deg');
      star.style.setProperty('--size', size+'px');
      star.style.setProperty('--trail', trail+'px');
      star.style.setProperty('--dur', dur+'s');
      star.style.setProperty('--tint', tint);

      star.innerHTML =
        "<div class='trail'></div>" +
        "<div class='spark' style='right:calc(50% + " + (trail*0.35) + "px); top:calc(50% - 2px);'></div>" +
        "<div class='spark' style='right:calc(50% + " + (trail*0.6)  + "px); top:calc(50% + 3px); animation-delay:0.15s;'></div>" +
        "<div class='head'></div>";

      doc.body.appendChild(star);
      setTimeout(function(){ star.remove(); }, dur*1000 + 100);
    }, delay);
  }

  const handler = function(e){
    const tab = e.target.closest('[role="tab"]');
    if (!tab) return;
    if (tab.getAttribute('aria-selected') === 'true') return; // already active, no-op
    spawnStar(0, true);
    spawnStar(90, false);
    spawnStar(220, false);
  };

  doc.__starHandler = handler;
  doc.addEventListener('click', handler, true);
})();
</script>
""", height=0)

# ─────────────────────────────────────────────
#  FETCH DATA
# ─────────────────────────────────────────────
metrics_data = fetch_metrics(st.session_state.data_limit)
alerts_data  = fetch_alerts(50)
hosts_data   = fetch_hosts()
devices_data = fetch_devices()

if _show_boot and _should_hide_boot(metrics_data, devices_data):
    components.html("""
    <script>
      const el = window.parent.document.getElementById('boot-overlay');
      if (el) { el.style.transition = 'opacity .4s ease'; el.style.opacity = '0'; }
    </script>
    """, height=0)
    time.sleep(0.4)
    _boot_ph.empty()
    st.session_state.boot_done = True

def is_private_ip(ip):
    parts = ip.split(".")
    return (parts[0] == "10" or
            parts[0] == "192" or
            (parts[0] == "172" and 16 <= int(parts[1]) <= 31))

def build_network_topology(metrics, devices=None):
    """Build live topology from metrics.
    Includes ALL hosts from recent metrics — does NOT require them
    to be in the devices list (catches recently pinged hosts even if
    the collector hasn't fully discovered them yet).
    Devices list is used only for enrichment (vendor, hostname, device_type)."""
    if not metrics:
        return {"nodes": [], "links": []}

    device_lookup = {}
    if devices:
        for d in devices:
            device_lookup[d.get("ip", "")] = d

    seen = {}
    host_count = {}
    for m in metrics:
        host = m.get("host", "")
        if not host:
            continue
        host_count[host] = host_count.get(host, 0) + 1
        if host in seen:
            continue

        ip_parts = host.split(".")
        is_ip = len(ip_parts) == 4 and all(p.isdigit() for p in ip_parts)

        dev_info = device_lookup.get(host, {})
        dtype = _DEVICE_TYPE_OVERRIDES.get(host) or dev_info.get("device_type") or "Unknown"

        host_data = [x for x in metrics if x.get("host") == host]
        avg_lat = sum(x.get("latency", 0) or 0 for x in host_data) / len(host_data)
        avg_err = sum(x.get("error_rate", 0) or 0 for x in host_data) / len(host_data)
        is_anom = any(x.get("is_anomaly", False) for x in host_data)

        seen[host] = {
            "id": host, "label": dev_info.get("hostname") or host, "ip": host,
            "device_type": dtype,
            "vendor": dev_info.get("vendor") or "Unknown",
            "status": "anomaly" if is_anom else "online",
            "latency": round(avg_lat, 2),
            "error_rate": round(avg_err, 2),
            "is_anomaly": is_anom,
            "is_ip": is_ip,
            "sample_count": host_count[host]
        }

    nodes = list(seen.values())

    hub = None
    for n in nodes:
        if n["is_ip"] and is_private_ip(n["ip"]) and n["ip"].endswith(".1"):
            hub = n["id"]
            n["device_type"] = "Router"
            break
    if not hub:
        private = [n for n in nodes if n["is_ip"] and is_private_ip(n["ip"])]
        if private:
            hub = max(private, key=lambda n: n["sample_count"])["id"]
    if not hub:
        ips = [n for n in nodes if n["is_ip"]]
        if ips:
            hub = max(ips, key=lambda n: n["sample_count"])["id"]
    if not hub:
        hub = max(nodes, key=lambda n: n["sample_count"])["id"]
    if not hub and nodes:
        hub = sorted(nodes, key=lambda n: n["id"])[0]["id"]

    links = []
    subnet_groups = {}
    for n in nodes:
        if n["is_ip"]:
            prefix = ".".join(n["ip"].split(".")[:3])
            subnet_groups.setdefault(prefix, []).append(n["id"])

    for prefix, members in subnet_groups.items():
        if hub in members:
            for m in members:
                if m != hub:
                    links.append({"source": hub, "target": m, "type": "ethernet", "latency": seen[m]["latency"]})
        elif len(members) > 1:
            m0 = members[0]
            for i in range(1, len(members)):
                links.append({"source": m0, "target": members[i], "type": "ethernet", "latency": seen[members[i]]["latency"]})

    linked = {l["source"] for l in links} | {l["target"] for l in links}
    for n in nodes:
        if n["id"] != hub and n["id"] not in linked:
            links.append({"source": hub, "target": n["id"], "type": "ethernet", "latency": n["latency"]})

    return {"nodes": nodes, "links": links}

_raw_topology = fetch_topology()
_metrics_topo = build_network_topology(metrics_data, devices_data)

if _raw_topology and _raw_topology.get("nodes") and _metrics_topo.get("links"):
    _api_nodes_by_id = {n["id"]: n for n in _raw_topology["nodes"]}
    merged_nodes = []
    for n in _metrics_topo["nodes"]:
        api_node = _api_nodes_by_id.get(n["id"], {})
        merged = {**n, **{k: v for k, v in api_node.items() if v and v != "Unknown"}}
        merged_nodes.append(merged)
    topology_data = {"nodes": merged_nodes, "links": _metrics_topo["links"]}
else:
    topology_data = _metrics_topo

# ─────────────────────────────────────────────
#  STATUS (minimal, no header/entry text)
# ─────────────────────────────────────────────
api_ok = len(metrics_data) > 0
sc, st_ = ("#00FF88", "ONLINE") if api_ok else ("#FF4DFF", "NO SIGNAL")

st.markdown(f"""
<div class='status-mini'>
  <div class='dot-pulse' style='background:{sc};color:{sc};'></div>
  <span style='color:{sc};'>{st_}</span>
</div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  NO DATA STATE
# ─────────────────────────────────────────────
if not metrics_data:
    st.markdown("""
    <div class='no-data'>
        <div style='font-family:Orbitron,sans-serif;color:#FF4DFF;font-size:1.1rem;margin-bottom:0.6rem;'>
            ✕ NO DATA RECEIVED
        </div>
        <div style='color:rgba(191,95,255,0.6);font-size:0.82rem;'>
            Make sure the API is running on
            <code style='color:#BF5FFF;'>http://localhost:8000</code>
            and <code style='color:#BF5FFF;'>simulator_v2.py</code> is generating data.
        </div>
    </div>""", unsafe_allow_html=True)
    st.stop()

# ─────────────────────────────────────────────
#  BUILD DATAFRAME — normalize timestamp column
# ─────────────────────────────────────────────
df = pd.DataFrame(metrics_data)

_ts_col = next((c for c in _TS_CANDIDATES if c in df.columns), None)
if _ts_col is None:
    st.error(f"Could not find a timestamp column. Available columns: {list(df.columns)}")
    st.stop()
if _ts_col != "ts":
    df = df.rename(columns={_ts_col: "ts"})
df["ts"] = pd.to_datetime(df["ts"])

anom_df    = df[df["is_anomaly"] == True]
avg_lat    = df["latency"].mean()
avg_traf   = df["traffic"].mean()
avg_err    = df["error_rate"].mean()
anom_count = int(df["is_anomaly"].sum())
anom_pct   = (anom_count / len(df)) * 100

# ─────────────────────────────────────────────
#  KPI CARDS
# ─────────────────────────────────────────────
st.markdown(f"""
<div class='kpi-grid'>
  <div class='kpi-card c1'>
    <div class='kpi-label'>Avg Latency</div>
    <div class='kpi-value'>{avg_lat:.1f}</div>
    <div class='kpi-unit'>milliseconds</div>
  </div>
  <div class='kpi-card c2'>
    <div class='kpi-label'>Avg Traffic</div>
    <div class='kpi-value'>{avg_traf:.1f}</div>
    <div class='kpi-unit'>Mbps</div>
  </div>
  <div class='kpi-card c3'>
    <div class='kpi-label'>Avg Error Rate</div>
    <div class='kpi-value'>{avg_err:.2f}</div>
    <div class='kpi-unit'>percent</div>
  </div>
  <div class='kpi-card c4'>
    <div class='kpi-label'>Anomalies</div>
    <div class='kpi-value'>{anom_count}</div>
    <div class='kpi-unit'>{anom_pct:.1f}% of {len(df)} samples</div>
  </div>
</div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  PLOTLY SHARED THEME
# ─────────────────────────────────────────────
BASE_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(8,3,20,0.82)",
    font=dict(family="Share Tech Mono, monospace", color="rgba(191,95,255,0.6)", size=11),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(123,0,255,0.3)", borderwidth=1,
                font=dict(color="#E0D7FF")),
    margin=dict(l=10, r=10, t=40, b=10),
    hovermode="x unified",
    hoverlabel=dict(bgcolor="rgba(20,0,45,0.9)", bordercolor="#BF5FFF",
                    font=dict(family="Share Tech Mono", color="#E0D7FF"))
)

GRID_X = dict(gridcolor="rgba(123,0,255,0.15)", showgrid=True, zeroline=False, color="rgba(191,95,255,0.4)")
GRID_Y = dict(gridcolor="rgba(123,0,255,0.15)", showgrid=True, zeroline=False, color="rgba(191,95,255,0.4)")

HOST_COLORS = {"R1": "#BF5FFF", "SW1": "#7B00FF", "WEB_SERVER": "#FF4DFF"}

def styled_line(metric, title, unit):
    fig = go.Figure()
    for host in df["host"].unique():
        hdf = df[df["host"] == host]
        fig.add_trace(go.Scatter(
            x=hdf["ts"], y=hdf[metric], mode="lines", name=host,
            line=dict(color=HOST_COLORS.get(host, "#BF5FFF"), width=1.8),
            fill="tozeroy",
            fillcolor="rgba(0,0,0,0)",
            hovertemplate=f"<b>{host}</b><br>%{{y:.2f}} {unit}<extra></extra>"
        ))
    if not anom_df.empty:
        fig.add_trace(go.Scatter(
            x=anom_df["ts"], y=anom_df[metric], mode="markers", name="Anomaly",
            marker=dict(color="#FF4DFF", size=9, symbol="x",
                        line=dict(width=2, color="#FF4DFF")),
            hovertemplate="<b>⚠ Anomaly</b><br>%{y:.2f} " + unit + "<extra></extra>"
        ))
    fig.update_layout(
        **BASE_LAYOUT,
        xaxis=GRID_X,
        yaxis=GRID_Y,
        title=dict(text=title, font=dict(family="Orbitron", color="#BF5FFF", size=12)),
        height=280
    )
    return fig

# ─────────────────────────────────────────────
#  TABS
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["⬛  Overview", "⚠  Alerts", "📈  Charts", "🌐  Network Topology"])

# ── TAB 1 ─────────────────────────────────────
with tab1:
    cl, cr = st.columns([1.1, 0.9], gap="large")

    with cl:
        st.markdown("<div class='sec-head'>// Host Status</div>", unsafe_allow_html=True)
        hs = df.groupby("host").agg(
            latency=("latency","mean"), error_rate=("error_rate","mean"),
            traffic=("traffic","mean"), anomalies=("is_anomaly","sum")
        ).round(2).reset_index()

        rows = ""
        for _, r in hs.iterrows():
            badge = f"<span class='badge-warn'>{int(r.anomalies)} alerts</span>" \
                    if r.anomalies > 0 else "<span class='badge-ok'>OK</span>"
            rows += f"""<tr>
                <td style='font-family:Share Tech Mono,monospace;color:#BF5FFF;'>{r.host}</td>
                <td>{r.latency:.1f} ms</td>
                <td>{r.error_rate:.2f}%</td>
                <td>{r.traffic:.1f} Mbps</td>
                <td>{badge}</td>
            </tr>"""
        st.markdown(f"""
        <table class='htable'>
          <thead><tr><th>Host</th><th>Latency</th><th>Errors</th><th>Traffic</th><th>Status</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>""", unsafe_allow_html=True)

    with cr:
        st.markdown("<div class='sec-head'>// Anomaly Distribution</div>", unsafe_allow_html=True)
        if anom_count > 0:
            ph = df.groupby("host")["is_anomaly"].sum().reset_index()
            ph = ph[ph["is_anomaly"] > 0]
            fig_pie = go.Figure(go.Pie(
                labels=ph["host"], values=ph["is_anomaly"], hole=0.6,
                marker=dict(colors=["#BF5FFF","#7B00FF","#FF4DFF"],
                            line=dict(color="#000000", width=2)),
                textfont=dict(family="Share Tech Mono", color="#E0D7FF", size=11),
            ))
            fig_pie.update_layout(
                **BASE_LAYOUT, height=260,
                xaxis=GRID_X, yaxis=GRID_Y,
                annotations=[dict(
                    text=f"<b>{anom_count}</b>",
                    font=dict(size=22, color="#FF4DFF", family="Orbitron"),
                    showarrow=False
                )]
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.markdown("""
            <div style='text-align:center;padding:3rem 0;color:#00FF88;
                        font-family:Share Tech Mono,monospace;font-size:0.85rem;
                        border:1px solid rgba(0,255,136,0.15);border-radius:10px;
                        background:rgba(0,255,136,0.02);'>
                ✓ ALL SYSTEMS NORMAL
            </div>""", unsafe_allow_html=True)

# ── TAB 2 ─────────────────────────────────────
with tab2:
    st.markdown("<div class='sec-head'>// Active Alerts</div>", unsafe_allow_html=True)
    adf = pd.DataFrame(alerts_data) if alerts_data else pd.DataFrame()
    if not adf.empty:
        _ats_col = next((c for c in _TS_CANDIDATES if c in adf.columns), None)
        if _ats_col and _ats_col != "ts":
            adf = adf.rename(columns={_ats_col: "ts"})
        if "ts" in adf.columns:
            adf["ts"] = pd.to_datetime(adf["ts"])
            adf = adf.sort_values("ts", ascending=False)

    ALL_ALERT_REASONS = [
        "Machine inaccessible ou câble débranché",
        "Interface réseau désactivée ou défectueuse",
        "Défaillance du lien WAN / Internet",
        "Défaillance routeur ou switch",
        "Pare-feu bloquant les communications",
        "Perte de paquets réseau",
        "Saturation de la bande passante",
        "Congestion / trafic réseau important",
        "Panne ou mauvaise configuration DNS",
        "Problème de configuration IP ou passerelle",
        "Forte utilisation CPU/RAM sur le serveur",
        "Latence réseau élevée",
        "Taux d'erreurs réseau élevé",
        "Cause indéterminée",
    ]

    reason_counts = adf["reason"].value_counts() if not adf.empty else pd.Series(dtype=int)
    reasons = ALL_ALERT_REASONS

    def _classify(reason):
        r = (reason or "").lower()
        if "inaccessible" in r or "débranch" in r or "debranch" in r or "dns" in r or "panne" in r:
            return "critical"
        if "latence" in r or "élevée" in r or "elevee" in r:
            return "warning"
        return "info"

    SEV_META = {
        "critical": dict(color="#FF4D6D", bg="rgba(255,77,109,0.35)", border="rgba(255,77,109,0.6)", icon="✕"),
        "warning":  dict(color="#FFC048", bg="rgba(255,192,72,0.35)", border="rgba(255,192,72,0.6)", icon="!"),
        "info":     dict(color="#BF5FFF", bg="rgba(191,95,255,0.35)", border="rgba(191,95,255,0.6)", icon="⚠"),
    }

    # ── Mouse-tracking glow (Linear.app-style) ──
    components.html("""
    <script>
    (function(){
      const doc = window.parent.document;
      if (doc.__sevGlowHandler) {
        doc.removeEventListener('mousemove', doc.__sevGlowHandler);
      }
      const handler = function(e){
        const cards = doc.querySelectorAll('.sev-card');
        cards.forEach(function(card){
          const r = card.getBoundingClientRect();
          if (e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom) {
            card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
            card.style.setProperty('--my', (e.clientY - r.top) + 'px');
          }
        });
      };
      doc.__sevGlowHandler = handler;
      doc.addEventListener('mousemove', handler);
    })();
    </script>
    """, height=0)

    active_cat = st.session_state.get("alert_active_cat", None)
    clicked_key = None
    CARDS_PER_ROW = 4

    for row_start in range(0, len(reasons), CARDS_PER_ROW):
        row_reasons = reasons[row_start:row_start + CARDS_PER_ROW]
        cols = st.columns(len(row_reasons), gap="small")
        for col, reason in zip(cols, row_reasons):
            kind = _classify(reason)
            m = SEV_META[kind]
            n = int(reason_counts.get(reason, 0))
            safe_key = re.sub(r'[^a-zA-Z0-9]+', '_', reason)[:40]
            with col:
                active_cls = "active" if active_cat == reason else ""
                card_html = f"""
                <div class='sev-card {active_cls}' style='--accent:{m["color"]};--glow:{m["bg"].replace("0.16","0.4")}'>
                    <div class='sev-card-icon'>{m["icon"]}</div>
                    <div class='sev-card-count'>{n}</div>
                    <div class='sev-card-title'>{m["icon"]} {reason}</div>
                </div>
                """
                st.markdown(re.sub(r'\n\s*', '', card_html), unsafe_allow_html=True)
                if st.button(reason, key=f"card_{safe_key}"):
                    clicked_key = reason

    if clicked_key is not None:
        st.session_state.alert_active_cat = None if active_cat == clicked_key else clicked_key
        st.rerun()

    if active_cat is not None:
        st.markdown("<div class='reset-filter-marker'></div>", unsafe_allow_html=True)
        if st.button("← Réduire", key="card_reset"):
            st.session_state.alert_active_cat = None
            st.rerun()

        prev_cat = st.session_state.get("alert_cat_prev")
        do_swipe = prev_cat != active_cat
        st.session_state.alert_cat_prev = active_cat
        panel_cls = "sev-panel-wrap swipe" if do_swipe else "sev-panel-wrap"

        def render_group_html(df_group, meta, title, cap=30):
            rows_html = []
            for _, r in df_group.head(cap).iterrows():
                ts_str = r.ts.strftime('%H:%M:%S') if "ts" in df_group.columns else "—"
                rows_html.append(f"""
                <div class='alert-row' style='--accent:{meta["color"]}'>
                    <span class='a-icon' style='background:{meta["bg"]};color:{meta["color"]};border:1px solid {meta["border"]};'>{meta["icon"]}</span>
                    <span class='a-host'>{r.host}</span>
                    <span class='a-reason'>{r.reason}</span>
                    <span class='a-time'>{ts_str}</span>
                </div>""")
            if not rows_html:
                rows_html.append("""
                <div style='text-align:center;padding:1.5rem;color:rgba(191,95,255,0.45);
                            font-family:Share Tech Mono,monospace;font-size:0.8rem;'>
                    ✓ No alerts for this category
                </div>""")
            html = f"""
            <div class='sev-group-head' style='color:{meta["color"]}'>
                <span>{meta["icon"]} {title}</span><span class='sev-count'>{len(df_group)}</span>
            </div>
            <div class='alert-panel'>{''.join(rows_html)}</div>
            """
            if len(df_group) > cap:
                html += f"<div class='alert-more'>+{len(df_group) - cap} more</div>"
            return html

        grp = adf[adf["reason"] == active_cat] if not adf.empty else pd.DataFrame()
        meta = SEV_META[_classify(active_cat)]
        panel_inner = render_group_html(grp, meta, active_cat, cap=30)

        final_html = f"<div class='{panel_cls}'>{panel_inner}</div>"
        final_html = re.sub(r'\n\s*', '', final_html)
        st.markdown(final_html, unsafe_allow_html=True)
    else:
        st.session_state.alert_cat_prev = None

    if not adf.empty:
        st.markdown("<div class='sec-head' style='margin-top:1.5rem;'>// Alert Reasons</div>", unsafe_allow_html=True)
        rc = adf["reason"].value_counts().reset_index()
        rc.columns = ["reason","count"]
        fig_bar = go.Figure(go.Bar(
            x=rc["count"], y=rc["reason"], orientation="h",
            marker=dict(
                color=rc["count"],
                colorscale=[[0,"#3C0078"],[0.5,"#7B00FF"],[1,"#FF4DFF"]],
                line=dict(color="rgba(0,0,0,0)")
            ),
            text=rc["count"], textposition="outside",
            textfont=dict(color="#E0D7FF", family="Share Tech Mono"),
        ))
        fig_bar.update_layout(
            **BASE_LAYOUT,
            height=200,
            xaxis=dict(showgrid=False, visible=False, color="rgba(191,95,255,0.4)"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)", color="rgba(191,95,255,0.4)")
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.markdown("""
        <div style='text-align:center;padding:3rem;color:#00FF88;
                    font-family:Share Tech Mono,monospace;
                    border:1px solid rgba(0,255,136,0.15);border-radius:10px;
                    background:rgba(0,255,136,0.02);'>
            ✓ ALL SYSTEMS NORMAL — NO ACTIVE ALERTS
        </div>""", unsafe_allow_html=True)

# ── TAB 3 ─────────────────────────────────────
with tab3:
    st.markdown("<div class='sec-head'>// Latency &amp; Error Rate</div>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.plotly_chart(styled_line("latency", "LATENCY", "ms"), use_container_width=True)
    with c2:
        st.plotly_chart(styled_line("error_rate", "ERROR RATE", "%"), use_container_width=True)

    st.markdown("<div class='sec-head'>// Network Traffic</div>", unsafe_allow_html=True)
    st.plotly_chart(styled_line("traffic", "TRAFFIC", "Mbps"), use_container_width=True)

# ============================================================
# TAB 4 - NETWORK TOPOLOGY WITH PING ANIMATION
# ============================================================
with tab4:
    """Enhanced Network Topology Tab with Animated Ping Effects"""
    import math as _math
    import time as _time

    st.markdown("<div class='sec-head'>// Network Topology — Live & Interactive</div>",
                unsafe_allow_html=True)

    # ============================================================
    # SESSION STATE FOR PING ANIMATION
    # ============================================================
    if "ping_in_progress" not in st.session_state:
        st.session_state.ping_in_progress = False
    if "ping_target" not in st.session_state:
        st.session_state.ping_target = None
    if "ping_result_data" not in st.session_state:
        st.session_state.ping_result_data = None
    if "ping_start_time" not in st.session_state:
        st.session_state.ping_start_time = None

    # Fetch fresh data (force_http to bypass WebSocket cache — need complete set, not latest 10)
    topo_metrics_data = fetch_metrics(st.session_state.data_limit, force_http=True)

    # ── Check for phone hotspot ──
    topo_api_resp = fetch_topology()
    hotspot_detected = topo_api_resp and topo_api_resp.get("hotspot_detected", False)

    if hotspot_detected:
        st.markdown("""
        <div style='text-align:center;padding:3rem;border:2px solid #FF4D4D;border-radius:14px;
                    background:rgba(255,77,77,0.08);margin:2rem 0;'>
            <div style='font-family:Orbitron,sans-serif;color:#FF4D4D;font-size:1.4rem;margin-bottom:0.8rem;'>
                🚫 PHONE HOTSPOT DETECTED
            </div>
            <div style='color:rgba(255,255,255,0.7);font-size:0.9rem;font-family:Share Tech Mono,monospace;
                        line-height:1.6;'>
                This network appears to be a phone hotspot.<br>
                Topology visualization is not available for hotspot networks.<br><br>
                Please connect to a standard router/switch network to view topology.
            </div>
        </div>""", unsafe_allow_html=True)
        st.stop()

    # ============================================================
    # BUILD TOPOLOGY FROM METRICS (uses unified builder)
    # ============================================================
    topo_devices = fetch_devices()
    final_topo = build_network_topology(topo_metrics_data, topo_devices)
    nodes_list = final_topo["nodes"]
    links_list = final_topo["links"]

    st.caption(f"📊 {len(nodes_list)} nodes · {len(links_list)} links · "
               f"{len(topo_metrics_data)} samples")

    if not nodes_list:
        st.markdown("""
        <div style='text-align:center;padding:3rem;color:#FF4DFF;
                    font-family:Share Tech Mono,monospace;'>
            ✕ NO TOPOLOGY DATA — Check that simulator + API are running
        </div>""", unsafe_allow_html=True)
    else:
        # ── Device style config ──
        STYLES = {
            "Router":  {"icon": "🌐", "color": "#2196F3", "symbol": "diamond", "size": 38},
            "Switch":  {"icon": "🔀", "color": "#00BCD4", "symbol": "square",  "size": 35},
            "Server":  {"icon": "🖥️", "color": "#FF9800", "symbol": "star",    "size": 32},
            "PC":      {"icon": "💻", "color": "#9C27B0", "symbol": "circle",  "size": 26},
            "Printer": {"icon": "🖨️", "color": "#8BC34A", "symbol": "square",  "size": 26},
            "TV":      {"icon": "📺", "color": "#E91E63", "symbol": "diamond", "size": 28},
            "Unknown": {"icon": "📡", "color": "#4CAF50", "symbol": "circle",  "size": 24}
        }

        def _deduce_icon_style(dtype, hostname=None):
            h = (hostname or "").lower()
            if "tv" in h or "tele" in h or "smarttv" in h:
                icon_uri = _get_icon_data_uri("tv", hostname)
                base = STYLES["TV"]
                return {**base, "icon_uri": icon_uri}
            icon_uri = _get_icon_data_uri(dtype, hostname)
            if icon_uri:
                base = next((s for k, s in STYLES.items() if k in dtype), STYLES["Unknown"])
                return {**base, "icon_uri": icon_uri}
            base = STYLES.get(dtype, STYLES["Unknown"])
            return {**base, "icon_uri": None}

        # Calculate positions (hub at center, others in circle)
        pos = {}
        hub_id = links_list[0]["source"] if links_list else nodes_list[0]["id"]
        pos[hub_id] = (0.0, 0.0)
        others = [n for n in nodes_list if n["id"] != hub_id]
        for i, n in enumerate(others):
            angle = 2 * _math.pi * i / max(len(others), 1) - _math.pi / 2
            pos[n["id"]] = (_math.cos(angle) * 1.1, _math.sin(angle) * 1.1)

        # ── Build figure ──
        fig = go.Figure()

        # Draw connection lines
        for lk in links_list:
            s, t = lk["source"], lk["target"]
            if s in pos and t in pos:
                x0, y0 = pos[s]
                x1, y1 = pos[t]
                target_node = next((n for n in nodes_list if n["id"] == t), None)
                lat = target_node.get("latency", 999) if target_node else 999
                is_anom = target_node.get("is_anomaly", False) if target_node else False

                if is_anom or lat > 200:
                    color, width = "#FF4DFF", 2
                elif lat > 100:
                    color, width = "#FFC107", 2
                else:
                    color, width = "#00FF88", 2.5

                fig.add_trace(go.Scatter(
                    x=[x0, x1, None], y=[y0, y1, None],
                    mode="lines",
                    line=dict(width=width, color=color),
                    hoverinfo="none", showlegend=False
                ))

                if 0 < lat < 999:
                    mx, my = (x0 + x1) / 2, (y0 + y1) / 2
                    fig.add_trace(go.Scatter(
                        x=[mx], y=[my], mode="text",
                        text=[f"{lat:.0f}ms"],
                        textfont=dict(color="rgba(255,255,255,0.7)", size=9,
                                      family="Share Tech Mono"),
                        hoverinfo="none", showlegend=False
                    ))

        # Draw nodes with multiple glow rings
        for node in nodes_list:
            nid = node["id"]
            if nid not in pos:
                continue
            x, y = pos[nid]
            dtype = node.get("device_type", "Unknown")
            hostname = node.get("label") or node.get("hostname") or ""
            style = _deduce_icon_style(dtype, hostname)
            is_anom = node.get("is_anomaly", False)
            lat = node.get("latency", 0)
            icon_uri = style.get("icon_uri")
            status_label = "UNIDENTIFIED" if "Unknown" in dtype else ("ANOMALY" if is_anom else "ONLINE")

            # Glow rings
            if "Unknown" in dtype:
                glow = "rgba(100,100,120,0.15)"
                glow2 = "rgba(100,100,120,0.07)"
            elif is_anom:
                glow = "rgba(255,77,255,0.25)"
                glow2 = "rgba(255,77,255,0.12)"
            elif lat > 200:
                glow = "rgba(255,193,7,0.2)"
                glow2 = "rgba(255,193,7,0.1)"
            elif lat > 100:
                glow = "rgba(255,193,7,0.15)"
                glow2 = "rgba(255,193,7,0.07)"
            else:
                glow = "rgba(0,255,136,0.15)"
                glow2 = "rgba(0,255,136,0.07)"

            fig.add_trace(go.Scatter(
                x=[x], y=[y], mode="markers",
                marker=dict(size=style["size"]*2.2, color=glow,
                            symbol=style["symbol"], line=dict(width=0)),
                hoverinfo="none", showlegend=False
            ))
            fig.add_trace(go.Scatter(
                x=[x], y=[y], mode="markers",
                marker=dict(size=style["size"]*1.5, color=glow2,
                            symbol=style["symbol"], line=dict(width=0)),
                hoverinfo="none", showlegend=False
            ))

            # Main node — image icon (layout image) or colored marker fallback
            if icon_uri:
                fig.add_layout_image(dict(
                    source=icon_uri, x=x, y=y,
                    xref="x", yref="y",
                    sizex=0.2, sizey=0.2,
                    xanchor="center", yanchor="middle",
                    layer="above"
                ))
                fig.add_trace(go.Scatter(
                    x=[x], y=[y], mode="text",
                    text=[f"{nid[:12]}{'...' if len(nid)>12 else ''}"],
                    textposition="bottom center",
                    textfont=dict(color="#E0D7FF", size=11, family="Share Tech Mono"),
                    hovertext=f"<b>{nid}</b><br>"
                              f"Type: {dtype}<br>"
                              f"Latency: {lat:.1f}ms<br>"
                              f"Status: {status_label}",
                    hoverinfo="text",
                    showlegend=False,
                    customdata=[nid]
                ))
            else:
                fig.add_trace(go.Scatter(
                    x=[x], y=[y], mode="markers+text",
                    marker=dict(
                        size=style["size"],
                        color=style["color"],
                        symbol=style["symbol"],
                        line=dict(width=3, color="#FFFFFF"),
                        opacity=1.0
                    ),
                    text=[f"{style['icon']} {nid[:12]}{'...' if len(nid)>12 else ''}"],
                    textposition="bottom center",
                    textfont=dict(color="#E0D7FF", size=11,
                                  family="Share Tech Mono"),
                    hovertext=f"<b>{style['icon']} {nid}</b><br>"
                              f"Type: {dtype}<br>"
                              f"Latency: {lat:.1f}ms<br>"
                              f"Status: {status_label}",
                    hoverinfo="text",
                    showlegend=False,
                    customdata=[nid]
                ))

        # Highlight currently pinging target
        if st.session_state.ping_in_progress and st.session_state.ping_target:
            target = st.session_state.ping_target
            if target in pos:
                tx, ty = pos[target]
                # Add a pulsing ring around the target
                for ring_size, ring_opacity in [(style["size"]*3, 0.4), (style["size"]*2.5, 0.6), (style["size"]*2, 0.8)]:
                    fig.add_trace(go.Scatter(
                        x=[tx], y=[ty], mode="markers",
                        marker=dict(size=ring_size, color="rgba(191,95,255,0.3)",
                                    symbol="circle", line=dict(width=2, color="rgba(191,95,255,0.8)")),
                        hoverinfo="none", showlegend=False
                    ))

        fig.update_layout(
            paper_bgcolor="rgba(8,7,15,0.95)",
            plot_bgcolor="rgba(8,7,15,0.95)",
            height=600,
            margin=dict(l=10, r=10, t=50, b=10),
            title=dict(
                text="🌐 NETWORK TOPOLOGY — CLICK ANY NODE TO PING",
                font=dict(family="Orbitron", color="#BF5FFF", size=14),
                x=0.5
            ),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                       range=[-1.7, 1.7]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                       range=[-1.7, 1.7], scaleanchor="x"),
            hovermode="closest",
            hoverlabel=dict(bgcolor="rgba(20,0,45,0.95)", bordercolor="#BF5FFF",
                            font=dict(color="#E0D7FF",
                                      family="Share Tech Mono", size=12)),
            dragmode="pan",
            clickmode='event+select'
        )

        # Display chart with click handling
        event = st.plotly_chart(fig, use_container_width=True,
                                on_select="rerun", key="topo_visual")

        # ============================================================
        # CLICK-TO-PING WITH ANIMATION
        # ============================================================
        if event and event.get("selection", {}).get("points"):
            pt = event["selection"]["points"][0]
            if "customdata" in pt and pt["customdata"]:
                clicked_target = pt["customdata"]
                # Set session state to trigger ping
                st.session_state.ping_target = clicked_target
                st.session_state.ping_in_progress = True
                st.session_state.ping_result_data = None
                st.session_state.ping_start_time = _time.time()
                st.rerun()

        # ============================================================
        # PING ANIMATION + RESULT
        # ============================================================
        if st.session_state.ping_in_progress and st.session_state.ping_target:
            target = st.session_state.ping_target

            # Check if we have a result yet
            if st.session_state.ping_result_data is None:
                elapsed = _time.time() - (st.session_state.ping_start_time or 0)

                if elapsed < 1.5:  # Show animation for 1.5 seconds
                    # ANIMATION PHASE - show radar effect
                    progress = min(elapsed / 1.5, 1.0)  # 0 to 1

                    st.markdown(f"""
                    <div style='
                        text-align:center;
                        padding:2rem;
                        background:rgba(191,95,255,0.05);
                        border:2px solid #BF5FFF;
                        border-radius:12px;
                        margin:1rem 0;
                        position:relative;
                        overflow:hidden;
                    '>
                        <div style='
                            font-size:1.3rem;
                            color:#BF5FFF;
                            font-family:Orbitron,sans-serif;
                            margin-bottom:0.5rem;
                        '>
                            📡 Pinging {target}...
                        </div>
                        <div style='
                            position:relative;
                            width:100%;
                            height:80px;
                            display:flex;
                            align-items:center;
                            justify-content:center;
                        '>
                            <div style='
                                position:absolute;
                                width:{40 + progress * 200}px;
                                height:{40 + progress * 200}px;
                                border:2px solid rgba(191,95,255,{0.8 - progress * 0.8});
                                border-radius:50%;
                                animation:radar 1.5s ease-out;
                            '></div>
                            <div style='
                                position:absolute;
                                width:30px;
                                height:30px;
                                background:radial-gradient(circle, #BF5FFF 0%, transparent 70%);
                                border-radius:50%;
                                animation:pulse-core 0.8s ease-in-out infinite;
                            '></div>
                        </div>
                        <div style='
                            color:rgba(191,95,255,0.7);
                            font-size:0.85rem;
                            font-family:Share Tech Mono,monospace;
                            margin-top:0.5rem;
                        '>
                            Transmitting ICMP packet... ({int(progress*100)}%)
                        </div>
                    </div>
                    <style>
                    @keyframes radar {{
                        0% {{ transform: scale(0.3); opacity: 1; }}
                        100% {{ transform: scale(2); opacity: 0; }}
                    }}
                    @keyframes pulse-core {{
                        0%, 100% {{ transform: scale(1); opacity: 1; }}
                        50% {{ transform: scale(1.3); opacity: 0.7; }}
                    }}
                    </style>
                    """, unsafe_allow_html=True)

                    _time.sleep(0.1)
                    st.rerun()
                else:
                    # Time to do the actual ping
                    result = ping_host(target)
                    st.session_state.ping_result_data = result
                    st.session_state.ping_in_progress = False
                    st.rerun()

        # Show ping result if we have one
        if (not st.session_state.ping_in_progress and
            st.session_state.ping_result_data is not None and
            st.session_state.ping_target):

            result = st.session_state.ping_result_data
            target = st.session_state.ping_target

            if result and result.get("latency") is not None:
                latency = result["latency"]
                is_anom = result.get("is_anomaly", False)

                if is_anom:
                    color, icon, text = "#FF4DFF", "⚠️", "ANOMALY DETECTED"
                elif latency < 30:
                    color, icon, text = "#00FF88", "✅", "EXCELLENT"
                elif latency < 100:
                    color, icon, text = "#00FF88", "🚀", "FAST"
                elif latency < 200:
                    color, icon, text = "#FFC107", "⏱️", "GOOD"
                else:
                    color, icon, text = "#FF4DFF", "🐌", "SLOW"

                st.markdown(f"""
                <div style='
                    background:rgba(0,0,0,0.15);
                    border:2px solid {color};
                    border-radius:12px;
                    padding:1.5rem;
                    margin:1rem 0;
                    text-align:center;
                    animation:result-pop 0.4s ease-out;
                '>
                    <div style='font-size:3rem; margin-bottom:0.3rem;'>{icon}</div>
                    <div style='
                        color:{color};
                        font-family:Orbitron,sans-serif;
                        font-size:1.8rem;
                        font-weight:800;
                        text-shadow:0 0 20px {color};
                    '>
                        {latency:.2f} ms
                    </div>
                    <div style='color:#E0D7FF;font-size:1.1rem;margin-top:0.3rem;'>
                        {text}
                    </div>
                    <div style='
                        color:rgba(191,95,255,0.7);
                        font-size:0.85rem;
                        margin-top:0.5rem;
                        font-family:Share Tech Mono,monospace;
                    '>
                        📡 {target}
                    </div>
                </div>
                <style>
                @keyframes result-pop {{
                    0% {{ transform: scale(0.8); opacity: 0; }}
                    50% {{ transform: scale(1.05); }}
                    100% {{ transform: scale(1); opacity: 1; }}
                }}
                </style>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style='
                    background:rgba(0,0,0,0.15);
                    border:2px solid #FF4DFF;
                    border-radius:12px;
                    padding:1.5rem;
                    margin:1rem 0;
                    text-align:center;
                    animation:result-pop 0.4s ease-out;
                '>
                    <div style='font-size:3rem;'>❌</div>
                    <div style='
                        color:#FF4DFF;
                        font-family:Orbitron,sans-serif;
                        font-size:1.8rem;
                        font-weight:800;
                    '>FAILED</div>
                    <div style='color:#E0D7FF;font-size:1rem;margin-top:0.3rem;'>
                        Host unreachable or timeout
                    </div>
                    <div style='
                        color:rgba(191,95,255,0.7);
                        font-size:0.85rem;
                        margin-top:0.5rem;
                    '>
                        📡 {target}
                    </div>
                </div>
                <style>
                @keyframes result-pop {{
                    0% {{ transform: scale(0.8); opacity: 0; }}
                    50% {{ transform: scale(1.05); }}
                    100% {{ transform: scale(1); opacity: 1; }}
                }}
                </style>
                """, unsafe_allow_html=True)

            # Clear button
            col_clear, _ = st.columns([1, 4])
            with col_clear:
                if st.button("🔄 Clear", key="clear_ping"):
                    st.session_state.ping_result_data = None
                    st.session_state.ping_target = None
                    st.rerun()

        # ============================================================
        # MANUAL PING SECTION (Backup)
        # ============================================================
        st.markdown("<div class='sec-head' style='margin-top:1.5rem;'>"
                    "// MANUAL PING</div>", unsafe_allow_html=True)
        pc1, pc2, pc3 = st.columns([2, 1, 1])
        with pc1:
            target_sel = st.selectbox("Device", [n["id"] for n in nodes_list],
                                      label_visibility="collapsed",
                                      key="manual_ping_sel")
        with pc2:
            custom_ip = st.text_input("Custom IP", placeholder="e.g. 8.8.8.8",
                                      label_visibility="collapsed",
                                      key="manual_ping_ip")
        with pc3:
            manual_ping = st.button("🚀 PING", type="primary",
                                    use_container_width=True,
                                    key="manual_ping_btn")

        if manual_ping:
            target = custom_ip.strip() if custom_ip.strip() else target_sel
            if target:
                # Use same session state flow
                st.session_state.ping_target = target
                st.session_state.ping_in_progress = True
                st.session_state.ping_result_data = None
                st.session_state.ping_start_time = _time.time()
                st.rerun()

        # ============================================================
        # LEGEND
        # ============================================================
        st.markdown("""
        <div style='margin-top:1.5rem;padding:1rem;background:rgba(20,0,45,0.6);
                    border-radius:10px;border:1px solid rgba(123,0,255,0.25);'>
          <div style='font-family:Share Tech Mono,monospace;color:#BF5FFF;
                      font-size:0.9rem;margin-bottom:0.5rem;'>LEGEND</div>
          <div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));
                      gap:0.4rem;font-family:Share Tech Mono,monospace;
                      color:#E0D7FF;font-size:0.75rem;'>
            <div>🖧 Router</div><div>🔄 Switch</div><div>🖥 Server</div>
            <div>💻 Client</div><div>📱 Phone</div><div>☁ Cloud</div>
            <div style='color:#00FF88;'>● Online</div>
            <div style='color:#FFC107;'>● Warning</div>
            <div style='color:#FF4DFF;'>● Anomaly</div>
          </div>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  FOOTER
# ─────────────────────────────────────────────
st.markdown(f"""
<div class='foot'>
  AI Network Copilot · Stage Project · {datetime.now().year}
  &nbsp;·&nbsp; {len(df)} samples · Hosts: {' · '.join(hosts_data)}
</div>""", unsafe_allow_html=True)