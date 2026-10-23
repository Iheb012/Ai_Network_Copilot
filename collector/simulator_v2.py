# collector/simulator_v2.py
# Real network monitoring system that pings hosts and stores metrics
# Includes automatic network discovery via ARP scanning
# Enhanced with automatic subnet detection, device fingerprinting, and topology mapping

import random
import sqlite3
import datetime
import time
import warnings
import logging
warnings.filterwarnings("ignore", category=SyntaxWarning, module="scapy")
logging.getLogger("scapy").setLevel(logging.ERROR)
import subprocess
import re
import sys
import os
import argparse
import socket
import struct
import importlib.util

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'network.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
try:
    import fcntl
    import array
except ImportError:
    # fcntl is not available on Windows
    fcntl = None
    array = None

# Add the project root to path to import detection modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from detection.rules import SEUILS, detecter_anomalie_seuils_adaptatifs

def _load_api_database_module():
    api_database_path = os.path.join(os.path.dirname(__file__), '..', 'api', 'database.py')
    spec = importlib.util.spec_from_file_location("api_database", api_database_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

_API_DATABASE = _load_api_database_module()
creer_base_de_donnees = _API_DATABASE.creer_base_de_donnees

# Try to import scapy for ARP scanning; if not available, fallback to file-based hosts.
# NOTE: scapy is only used for OPTIONAL Linux/Mac ARP scans and traceroute — the
# Windows discovery path (discover_local_devices_win) is 100% subprocess-based.
# Import it quietly: on machines without Npcap it logs a scary "pcap service is
# not running" warning at import time, which is irrelevant to the collector.
try:
    with open(os.devnull, "w") as _devnull, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _saved_err = sys.stderr
        sys.stderr = _devnull
        try:
            from scapy.all import ARP, Ether, srp, conf, sr1, IP, ICMP, TCP
        finally:
            sys.stderr = _saved_err
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Network discovery disabled. Install with: pip install scapy")

# ── Network interface used for ARP scans ─────────────────────────────────────
# Auto-detected from the system routing table (the interface that reaches the
# internet), so it works on any machine. To force a specific adapter, set the
# SCAPY_IFACE environment variable (run scapy's get_if_list() to see the names).
_SCAPY_IFACE_CACHE = None


def get_scapy_iface():
    """Return the interface scapy should use for ARP scans."""
    global _SCAPY_IFACE_CACHE
    if _SCAPY_IFACE_CACHE is not None:
        return _SCAPY_IFACE_CACHE
    override = os.getenv("SCAPY_IFACE", "").strip()
    if override:
        _SCAPY_IFACE_CACHE = override
        return override
    iface = None
    try:
        iface = conf.route.route("8.8.8.8")[0]      # interface for the default route
    except Exception:
        pass
    if not iface or str(iface) in ("lo", "lo0"):
        try:
            iface = conf.iface                       # scapy's own default
        except Exception:
            pass
    _SCAPY_IFACE_CACHE = iface
    print(f"[*] Using network interface: {iface}")
    return iface


# Try to import pysnmp for SNMP support
try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    print("Warning: pysnmp not installed. SNMP support disabled. Install with: pip install pysnmp")


def get_default_gateway_linux():
    """Get the default gateway on Linux systems."""
    try:
        with open("/proc/net/route", "r") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] == "00000000" and int(fields[3], 16) & 2:
                    # Extract gateway IP and convert to dotted quad
                    gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
                    return gateway
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return None


def get_interface_for_destination(dest_ip):
    """Get the network interface used to reach a destination IP."""
    try:
        # Try to get the interface used to reach the destination
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable
        s.connect((dest_ip, 1))
        ip_address = s.getsockname()[0]
        s.close()

        # Now get interface name for this IP
        # This is platform-dependent; on Linux we can parse /proc/net/route
        # For simplicity, we'll return the IP and let the caller determine subnet
        return ip_address
    except Exception:
        return None


def get_windows_subnets():
    """Detect ALL local subnets on Windows using ipconfig.
    Returns a list of subnet strings (e.g. ['192.168.1.0/24', '192.168.43.0/24']).
    Handles multiple network adapters (Ethernet, Wi-Fi, phone hotspots, etc.)."""
    try:
        output = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
        adapters = output.stdout.split('\n\n')
        subnets = []
        seen = set()
        for block in adapters:
            ip = None
            mask = None
            for line in block.split('\n'):
                m = re.search(r'IPv4[^.]+[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    ip = m.group(1)
                m = re.search(r'Subnet[^.]+[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if m:
                    mask = m.group(1)
            if ip and mask and not ip.startswith('169.254.'):
                ip_parts = [int(x) for x in ip.split('.')]
                mask_parts = [int(x) for x in mask.split('.')]
                network = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
                bits = sum(bin(x).count('1') for x in mask_parts)
                cidr = f"{network}/{bits}"
                if cidr not in seen:
                    seen.add(cidr)
                    subnets.append(cidr)
                    print(f"[*] Detected subnet: {cidr} from {ip}")
        if subnets:
            return subnets
    except Exception:
        pass
    return None


def get_local_subnet():
    """Automatically detect the local network subnet (Windows + Linux).
    Returns the first detected subnet for backward compatibility."""
    subnets = get_windows_subnets()
    if subnets:
        return subnets[0]

    # Linux: try to get default gateway
    try:
        gateway = get_default_gateway_linux()
        if gateway:
            gateway_parts = gateway.split('.')
            if len(gateway_parts) == 4:
                subnet = f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}.0/24"
                return subnet

        # Fallback: try to get local IP and assume /24
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        local_parts = local_ip.split('.')
        if len(local_parts) == 4:
            subnet = f"{local_parts[0]}.{local_parts[1]}.{local_parts[2]}.0/24"
            return subnet

    except Exception as e:
        print(f"Warning: Could not auto-detect subnet: {e}")

    # Final fallback
    return "192.168.1.0/24"


def get_default_gateway_windows():
    """Return the IPv4 default gateway from the Windows routing table (or None)."""
    try:
        route_out = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-NetRoute -DestinationPrefix "0.0.0.0/0" | '
             'Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop'],
            capture_output=True, text=True, timeout=5
        )
        if route_out.returncode == 0:
            gw = route_out.stdout.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', gw):
                return gw
    except Exception:
        pass
    return None


def _subnet_contains_ip(subnet, ip):
    """Return True if `ip` falls inside `subnet` (e.g. '192.168.1.0/24')."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except Exception:
        return False


def get_primary_subnet(subnets, gateway_ip=None):
    """
    Pick the subnet that actually carries the machine's traffic.
    Virtual adapters (Docker/VMware/WSL) have no default gateway and would
    pollute discovery with wrong IPs, so we restrict sweeping to the subnet
    that contains the default gateway when one is known.
    """
    if gateway_ip:
        for s in subnets:
            if _subnet_contains_ip(s, gateway_ip):
                print(f"[*] Primary subnet (contains gateway {gateway_ip}): {s}")
                return s
    return subnets[0] if subnets else None


def snmp_get(oid, host, community='public', port=161, timeout=1, retries=1):
    """
    Perform an SNMP GET operation on a host.
    Returns the value if successful, None otherwise.
    """
    if not SNMP_AVAILABLE:
        return None

    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community, mpModel=0),
                   UdpTransportTarget((host, port), timeout=timeout, retries=retries),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )

        if error_indication:
            return None
        elif error_status:
            return None
        else:
            for var_bind in var_binds:
                return str(var_bind[1])
    except Exception:
        return None


def snmp_get_system_info(host, community='public'):
    """
    Get basic system information from a device via SNMP.
    Returns a dictionary with system info or empty dict if failed.
    """
    if not SNMP_AVAILABLE:
        return {}

    # Common OIDs for system information
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',      # System Description
        'sysObjectID': '1.3.6.1.2.1.1.2.0',   # System Object ID
        'sysUpTime': '1.3.6.1.2.1.1.3.0',     # System Up Time
        'sysContact': '1.3.6.1.2.1.1.4.0',    # System Contact
        'sysName': '1.3.6.1.2.1.1.5.0',       # System Name
        'sysLocation': '1.3.6.1.2.1.1.6.0'    # System Location
    }

    result = {}
    for key, oid in oids.items():
        value = snmp_get(oid, host, community)
        if value is not None:
            result[key] = value

    return result


def snmp_get_interfaces(host, community='public'):
    """
    Get interface information from a device via SNMP.
    Returns a list of interface dictionaries or empty list if failed.
    """
    if not SNMP_AVAILABLE:
        return []

    try:
        # IF-MIB::ifDescr - Interface descriptions
        # IF-MIB::ifType - Interface types
        # IF-MIB::ifMtu - Interface MTU
        # IF-MIB::ifSpeed - Interface speed
        # IF-MIB::ifPhysAddress - Interface MAC address
        # IF-MIB::ifAdminStatus - Interface admin status
        # IF-MIB::ifOperStatus - Interface operational status

        base_oid = '1.3.6.1.2.1.2.2.1'  # ifEntry

        # We'll walk the ifTable to get all interfaces
        # For simplicity, we'll just get a few key fields for the first few interfaces

        interfaces = []
        for i in range(1, 11):  # Get first 10 interfaces
            if_index = f"{base_oid}.{i}"

            # Get interface description
            if_descr = snmp_get(f"{if_index}.2", host, community)
            if if_descr is None:
                break  # No more interfaces

            # Get other interface properties
            if_type = snmp_get(f"{if_index}.3", host, community)
            if_mtu = snmp_get(f"{if_index}.4", host, community)
            if_speed = snmp_get(f"{if_index}.5", host, community)
            if_physaddr = snmp_get(f"{if_index}.6", host, community)
            if_admin_status = snmp_get(f"{if_index}.7", host, community)
            if_oper_status = snmp_get(f"{if_index}.8", host, community)

            # Parse MAC address if present
            mac_address = None
            if if_physaddr:
                try:
                    # Convert hex string to MAC format
                    hex_parts = if_physaddr.replace(':', '').replace('-', '')
                    if len(hex_parts) == 12:
                        mac_address = ':'.join([hex_parts[i:i+2] for i in range(0, 12, 2)])
                except:
                    pass

            interface = {
                'index': i,
                'description': if_descr,
                'type': if_type,
                'mtu': int(if_mtu) if if_mtu and if_mtu.isdigit() else None,
                'speed': int(if_speed) if if_speed and if_speed.isdigit() else None,
                'mac_address': mac_address,
                'admin_status': if_admin_status,
                'oper_status': if_oper_status
            }

            interfaces.append(interface)

        return interfaces
    except Exception:
        return []


def mac_vendor_lookup(mac):
    """
    Look up vendor information for a MAC address.
    Uses a simple OUI lookup (first 3 octets).
    """
    if not mac or len(mac) < 8:
        return "Unknown"

    # Extract OUI (first 3 octets, separated by colons, hyphens, or nothing)
    oui = mac.upper().replace('-', ':').split(':')[0:3]
    if len(oui) < 3:
        return "Unknown"

    oui_str = ':'.join(oui)

    # Common OUI mappings
    oui_database = {
        # Network infrastructure
        "00:00:0C": "Cisco",        "00:01:42": "Cisco",
        "00:01:64": "HP",           "00:08:9B": "Juniper",
        "00:0C:51": "Avaya",        "00:14:3B": "Aruba",
        "00:14:5A": "Cisco",        "00:16:CB": "Ubiquiti",
        "00:16:D3": "Cisco",        "00:16:E6": "Cisco",
        "00:1A:92": "Juniper",      "00:1C:C4": "Cisco",
        "00:21:9A": "Palo Alto",    "00:26:6D": "Cisco",
        "00:09:5B": "Netgear",      "00:11:11": "Linksys",
        "00:11:24": "Netgear",      "00:1F:5B": "Netgear",
        "D8:9D:67": "TP-Link",      "F4:F5:D8": "Ubiquiti",
        "FC:FB:FB": "Netgear",
        # Apple / iPhone / iPad / Mac
        "00:03:93": "Apple",        "00:06:6B": "Apple",
        "00:0A:95": "Apple",        "00:0E:0C": "Apple",
        "00:17:F2": "Apple",        "00:18:01": "Apple",
        "00:1A:A5": "Apple",        "00:1E:65": "Apple",
        "00:21:70": "Apple",        "00:25:00": "Apple",
        "04:3E:8C": "Google",       "10:08:B1": "Apple",
        "34:12:98": "Apple",        "4C:32:75": "Apple",
        "60:03:08": "Apple",        "68:5D:43": "Apple",
        "7C:11:BE": "Apple",        "88:66:5A": "Apple",
        "AC:DE:48": "Apple",        "B8:AE:ED": "Apple",
        "D0:03:4B": "Apple",        "D4:61:9D": "Apple",
        "E0:DA:F5": "Apple",        "F0:18:98": "Apple",
        "F8:0C:F3": "Apple",
        # Samsung
        "00:13:20": "Samsung",      "00:19:B9": "Samsung",
        "00:26:37": "Samsung",      "2C:BE:EB": "Samsung",
        "3C:2E:FF": "Samsung",      "48:D8:FE": "Samsung",
        "5C:51:88": "Samsung",      "8C:4B:14": "Samsung",
        "D0:17:C2": "Samsung",
        # Google / Pixel
        "18:9E:FC": "Google",       "40:BD:32": "Google",
        "04:3E:8C": "Google",       "8C:6B:44": "Google",
        # Xiaomi
        "28:16:AD": "Xiaomi",       "64:6E:6C": "Xiaomi",
        "9C:A2:F4": "Xiaomi",       "BC:76:70": "Xiaomi",
        "F0:03:8C": "Xiaomi",
        # Huawei
        "0C:96:BF": "Huawei",       "48:7A:DA": "Huawei",
        "8C:8C:A2": "Huawei",       "CC:6D:A0": "Huawei",
        "F4:96:34": "Huawei",
        # Mobile / Consumer
        "00:11:88": "Motorola",     "00:15:C5": "Brother",
        "00:1D:D8": "Brother",      "00:04:23": "Amazon",
        "00:28:F8": "Amazon",       "E4:5F:01": "Amazon",
        "DC:A6:32": "Raspberry Pi",
        # PC / Laptop
        "00:01:E6": "Intel",        "00:07:E9": "Intel",
        "00:0A:27": "Intel",        "00:1B:21": "Intel",
        "00:A0:C9": "Intel",        "8C:E9:EE": "Intel",
        "3C:46:D8": "Intel",        "4C:79:6E": "Intel",
        "5C:F9:DD": "Intel",        "98:4F:EE": "Intel",
        "A0:AF:06": "Intel",        "B4:96:91": "Intel",
        "E0:2C:35": "Intel",        "F8:BC:12": "Intel",
        "00:0F:FE": "Dell",
        "00:10:18": "Dell",         "00:11:43": "Dell",
        "00:12:79": "Dell",         "00:14:22": "Dell",
        "00:14:A5": "Dell",         "00:1B:44": "Dell",
        "00:1C:42": "Dell",         "00:1D:09": "Dell",
        "00:22:3D": "Dell",         "00:22:B0": "Dell",
        "00:23:AE": "Dell",         "00:24:A5": "Dell",
        "00:25:64": "Dell",         "00:25:90": "Dell",
        "00:25:CF": "Dell",         "00:26:B9": "Dell",
        "00:27:13": "Dell",         "00:29:A5": "Dell",
        "00:11:32": "Lenovo",       "00:1C:14": "Lenovo",
        "00:1B:C5": "HP",           "00:1C:23": "HP",
        "00:1C:C8": "HP",           "00:1D:7E": "HP",
        "00:1E:68": "HP",           "00:1F:29": "HP",
        "00:1F:3C": "HP",           "00:1F:F3": "HP",
        "00:21:5D": "HP",           "00:22:64": "HP",
        "00:23:G": "HP",            "00:24:81": "HP",
        "00:25:4B": "HP",           "00:25:BC": "HP",
        "00:26:5A": "HP",           "00:26:B0": "HP",
        "00:26:F2": "HP",           "00:27:10": "HP",
        "00:27:19": "HP",           "00:27:22": "HP",
        "00:27:35": "HP",           "00:27:8A": "HP",
        "00:27:C6": "HP",           "00:29:37": "HP",
        "00:2B:67": "HP",           "00:10:A4": "HP",
        "00:10:B5": "HP",           "00:13:CE": "HP",
        "00:16:EA": "HP",           "00:18:DE": "HP",
        "00:1A:7D": "HP",           "00:1A:A0": "HP",
        "00:01:64": "HP",           "00:06:5B": "HP",
        "00:0C:42": "HP",
        # Virtual / Software
        "00:05:5D": "Microsoft",    "00:15:5D": "Microsoft",
        "00:12:3F": "Microsoft",    "00:0A:F5": "VMware",
        "00:0C:29": "VMware",       "00:50:56": "VMware",
        "00:16:3E": "Xensource",
        # Networking / Legacy
        "00:02:B3": "3Com",         "00:08:C7": "IBM",
        "00:12:BF": "IBM",          "00:15:99": "IBM",
        "00:20:A6": "IBM",          "00:14:BF": "Brocade",
        "00:30:48": "Digital",      "00:90:27": "3Com",
        "00:A0:24": "Compaq",       "00:E0:64": "3Com",
        "00:2B:": "Dell",
        # NIC / Chipset
        "00:E0:4C": "Realtek",
    }

    return oui_database.get(oui_str, "Unknown")


def get_hostname(ip, timeout=1.0):
    """Resolve hostname for an IP address using reverse DNS (bounded).

    socket.gethostbyaddr has no timeout of its own and on Windows hangs
    ~10s per unresolvable IP (the socket default timeout is ignored by the
    Windows resolver). We run it in a daemon thread and abandon it after
    `timeout` seconds so discovery never blocks on DNS."""
    import threading
    result = {}

    def _resolve():
        try:
            result["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result["name"] = None

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None  # abandoned thread is daemon, dies with the process
    return result.get("name")


def scan_ports(host, ports=[22, 80, 443, 3389], timeout=1):
    """
    Scan specific ports on a host to determine device type.
    Returns a list of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def traceroute(host, max_hops=30):
    """
    Perform a basic traceroute to the host.
    Returns a list of hops (IP addresses).
    """
    if not SCAPY_AVAILABLE:
        return []  # Skip traceroute if scapy not available

    try:
        hops = []
        for ttl in range(1, max_hops + 1):
            # Send ICMP packet with TTL
            pkt = IP(dst=host, ttl=ttl) / ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)

            if resp is None:
                # No response
                hops.append("*")
            elif resp.type == 3:  # Destination unreachable
                hops.append(resp.src)
                break
            elif resp.type == 0:  # Echo reply
                hops.append(resp.src)
                break
            else:
                hops.append(resp.src)

            # Stop if we've reached the destination
            if resp and resp.src == host:
                break

        return hops
    except Exception as e:
        print(f"Traceroute failed for {host}: {e}")
        return []


def ping_sweep(subnet="192.168.1.0/24", timeout=900, max_workers=64):
    """Fast parallel ping sweep to discover active hosts on a subnet.
    Uses bounded parallelism + a tiny inter-batch delay to avoid ICMP
    rate-limiting on consumer routers while staying ~5x faster than the
    old 20-worker/1s-timeout sweep.
    Returns list of IPs that responded."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor, as_completed

    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    print(f"[*] Ping sweeping {len(hosts)} IPs (timeout={timeout}ms, {max_workers} workers)...")

    def _ping(ip):
        try:
            r = subprocess.run(
                ['ping', '-n', '1', '-w', str(timeout), ip],
                capture_output=True, text=True, timeout=(timeout/1000)+0.5
            )
            return ip, r.returncode == 0
        except:
            return ip, False

    active = []
    # Reuse ONE executor across batches (avoids pool teardown between batches)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for batch_start in range(0, len(hosts), max_workers):
            batch = hosts[batch_start:batch_start + max_workers]
            futs = {ex.submit(_ping, ip): ip for ip in batch}
            for f in as_completed(futs):
                ip, ok = f.result()
                if ok:
                    active.append(ip)
            done = min(batch_start + max_workers, len(hosts))
            print(f"   Sweep progress: {done}/{len(hosts)} ({len(active)} found)")
            # Small delay between batches to let router's ICMP budget replenish
            if batch_start + max_workers < len(hosts):
                time.sleep(0.1)

    print(f"[*] Ping sweep complete: {len(active)} active hosts found")
    return active


def tcp_probe(ip, ports=None, timeout=0.8):
    """Try TCP connection to ports as a lightweight probe for ping-resistant devices.
    Uses non-blocking connect with short timeout. Returns True if any port accepts."""
    if ports is None:
        ports = (80, 443, 8080)
    import socket
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return True
        except Exception:
            pass
    return False


def is_broadcast_or_network(ip):
    """Check if an IP is a broadcast or network address (x.x.x.0 or x.x.x.255)."""
    parts = ip.split('.')
    return len(parts) == 4 and (parts[3] == '0' or parts[3] == '255')


def is_bad_network_ip(ip):
    """Return True for IPs that should NEVER be treated as LAN devices:
    multicast (224.0.0.0/4 — the old filter only caught 224/239 and let
    225–238.x.x slip through as fake devices), link-local APIPA, network/
    broadcast addresses and loopback."""
    try:
        first = int(ip.split('.')[0])
    except (ValueError, IndexError):
        return True
    if 224 <= first <= 239:      # full multicast range
        return True
    if ip.startswith('169.254.'):      # APIPA / link-local
        return True
    if ip.startswith('127.'):          # loopback
        return True
    return is_broadcast_or_network(ip)


def tcp_sweep(subnet="192.168.1.0/24", ports=(80, 443), timeout=0.2):
    """Fast TCP connect scan of a subnet on specific ports.
    Catches devices that block ICMP (ping) but respond to TCP.
    Uses very short timeout (200ms) and batched parallelism."""
    import ipaddress
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    found = []
    print(f"[*] TCP sweep {len(hosts)} IPs on ports {ports} (timeout={timeout}s)...")
    def _probe(ip):
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return ip
                s.close()
            except Exception:
                pass
        return None
    # Small batches to avoid overwhelming the network
    BATCH = 30
    for start in range(0, len(hosts), BATCH):
        batch = hosts[start:start + BATCH]
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=BATCH) as ex:
            futs = {ex.submit(_probe, ip): ip for ip in batch}
            for f in as_completed(futs):
                ip = f.result()
                if ip:
                    found.append(ip)
    print(f"[*] TCP sweep complete: {len(found)} additional hosts found")
    return found


def broadcast_ping(subnets=None):
    """Send a broadcast ping to populate the ARP cache with ALL active devices.
    Windows: ping -b <broadcast> sends an ICMP echo to every host on the subnet.
    This forces all devices to respond, populating the ARP/neighbor cache."""
    if subnets is None:
        subs = get_windows_subnets()
        if not subs:
            subs = [get_local_subnet()]
    else:
        subs = subnets
    for subnet in subs:
        try:
            net = subnet.split('/')[0]
            parts = net.split('.')
            if len(parts) == 4:
                bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                subprocess.run(
                    ['ping', '-n', '1', '-w', '500', '-b', bcast],
                    capture_output=True, timeout=2
                )
                print(f"[*] Broadcast ping sent to {bcast}")
        except Exception:
            pass


VALID_NEIGHBOR_STATES = {"Reachable", "Stale", "Delay", "Probe", "Permanent"}
ALL_ZEROS_MAC = "00:00:00:00:00:00"

def _is_valid_neighbor(ip, mac, state):
    """Return True only if this neighbor entry represents a real device.
    Filters out:
    - Multicast / link-local / broadcast / loopback addresses
    - Unreachable/Incomplete entries (no device at this IP)
    - Entries with all-zeros MAC (fake placeholder)
    """
    if ip and is_bad_network_ip(ip):
        return False
    if state and state not in VALID_NEIGHBOR_STATES:
        return False
    if mac and mac == ALL_ZEROS_MAC:
        return False
    return True


def parse_arp_table():
    """Read and parse Windows ARP/neighbor table.
    Tries PowerShell Get-NetNeighbor first (more complete), falls back to arp -a.
    Only returns entries that represent REAL devices (valid MAC + confirmed state).
    Returns list of device dicts (ip, mac, vendor, hostname)."""
    if sys.platform != "win32":
        return _parse_arp_table_linux()

    devices = []
    seen_ips = set()

    # Method 1: PowerShell Get-NetNeighbor (complete neighbor cache)
    try:
        ps_cmd = [
            'powershell', '-NoProfile', '-Command',
            'Get-NetNeighbor -AddressFamily IPv4 | '
            'Select-Object IPAddress, LinkLayerAddress, State | '
            'ConvertTo-Csv -NoTypeInformation'
        ]
        ps_out = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=10)
        if ps_out.returncode == 0:
            for line in ps_out.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('"IPAddress"'):
                    continue
                parts = line.strip('"').split('","')
                if len(parts) < 1:
                    continue
                ip = parts[0]
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    continue
                mac_raw = parts[1].replace('-', ':').lower() if len(parts) > 1 and parts[1] else ''
                state = parts[2].strip() if len(parts) > 2 else ''
                if is_bad_network_ip(ip) or ip in seen_ips:
                    continue
                if len(mac_raw) >= 12:
                    mac = mac_raw if ':' in mac_raw else ':'.join(mac_raw[i:i+2] for i in range(0, 12, 2))
                else:
                    mac = None
                # Only keep real devices (valid MAC + confirmed state)
                if not _is_valid_neighbor(ip, mac, state):
                    continue
                seen_ips.add(ip)
                vendor = mac_vendor_lookup(mac) if mac else "Unknown"
                # hostname is left None here on purpose: it is resolved in the
                # parallel enrichment phase (per-IP DNS here was the slowest
                # part of discovery — ~10s per unresolvable host).
                print(f"   [ARP] {ip} mac={mac or '?'} state={state}")
                devices.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": None, "device_type": "Unknown",
                    "ports": [], "trace_route": []
                })
    except Exception as e:
        print(f"[!] Get-NetNeighbor failed: {e}")

    # Method 2: Fallback to arp -a for entries PowerShell might have missed
    try:
        output = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        if output.returncode == 0:
            for line in output.stdout.split('\n'):
                match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').lower()
                    if is_bad_network_ip(ip) or ip in seen_ips:
                        continue
                    if mac == ALL_ZEROS_MAC:
                        continue
                    seen_ips.add(ip)
                    vendor = mac_vendor_lookup(mac)
                    # hostname resolved in the parallel enrichment phase (see above)
                    print(f"   [ARP] {ip} mac={mac} (from arp -a)")
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": None, "device_type": "Unknown",
                        "ports": [], "trace_route": []
                    })
    except Exception as e:
        print(f"[!] arp -a failed: {e}")
    return devices


def resolve_hostname_win(ip):
    """Windows-friendly hostname resolution: tries ping -a first, then nbtstat, then DNS."""
    # Method 1: ping -a (reverse DNS)
    try:
        r = subprocess.run(['ping', '-a', '-n', '1', '-w', '500', ip],
                           capture_output=True, text=True, timeout=2)
        # Output: "Pinging HOSTNAME [IP]..."
        m = re.search(r'Pinging\s+(\S+)\s+\[', r.stdout, re.IGNORECASE)
        if m:
            name = m.group(1)
            if name != ip and not name.startswith('?'):
                return name
    except Exception:
        pass

    # Method 2: nbtstat -A (NetBIOS name)
    try:
        r = subprocess.run(['nbtstat', '-A', ip], capture_output=True, text=True, timeout=3)
        m = re.search(r'^\s+(\S+)\s+<00>\s+UNIQUE', r.stdout, re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass

    # Method 3: standard reverse DNS
    return get_hostname(ip)


def _mac_is_randomized(mac):
    """True if the MAC has the locally-administered bit set (0x02 in the first
    octet) — i.e. a modern phone/tablet using Wi-Fi privacy (randomized) MACs."""
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


# ── Manually-confirmed devices (user-provided ground truth) ────────────────
# Keyed by MAC so the label follows the device even if DHCP hands it a new IP.
# The heuristics below cannot see these (random/private MACs or quiet devices),
# so the user tags them once and the collector applies the label forever.
MANUAL_DEVICE_TYPES = {
    "c6:39:75:0a:a8:c8": "Cloud Camera System",   # house camera system (.12)
    "94:b3:f7:ec:8e:87": "Smart TV",               # living room TV (.20)
}


def classify_device(device):
    """Enhanced device-type detection.

    Combines, in priority order: user-confirmed MAC override, hostname
    patterns, randomized-MAC (privacy phones), open-port signatures, and
    MAC-vendor category. Falls back to 'Unknown' rather than guessing, so the
    dashboard shows a generic node instead of a confidently-wrong label.
    """
    ip = (device.get("ip") or "").strip()
    hostname = (device.get("hostname") or "").lower().strip()
    vendor = (device.get("vendor") or "").lower().strip()
    mac = (device.get("mac") or "").lower().replace("-", ":")
    ports = set(device.get("ports") or [])

    # ── 0) User-confirmed override wins over every heuristic ──
    manual = MANUAL_DEVICE_TYPES.get(mac)
    if manual:
        return manual

    # ── 1) Hostname is the strongest, most reliable signal ──
    if hostname and hostname != "null":
        if any(k in hostname for k in ("iphone", "ipad", "ipod")):
            return "iPhone/iPad"
        if any(k in hostname for k in ("printer", "print-", "epson", "canon",
                                       "brother", "lexmark", "ricoh", "xerox",
                                       "hp-laserjet", "hp-deskjet", "samsung-m")):
            return "Printer"
        if any(k in hostname for k in ("router", "gateway", "mikrotik",
                                       "openwrt", "wrt", "ap-")):
            return "Router"
        if any(k in hostname for k in ("camera", "cam-", "ipcam", "reolink",
                                       "hikvision", "dahua", "wyze", "nvr")):
            return "IP Camera"
        if any(k in hostname for k in ("echo", "alexa", "google-home", "nest",
                                       "sonos", "speaker", "soundbar", "jbl")):
            return "Smart Speaker"
        if any(k in hostname for k in ("playstation", "ps4", "ps5", "xbox",
                                       "nintendo", "switch", "wii", "steamdeck")):
            return "Game Console"
        # Phone BEFORE TV: brands like Samsung/LG make both, but a hostname
        # containing "galaxy"/"android"/"pixel"... is unambiguously a phone.
        if any(k in hostname for k in ("android", "pixel", "galaxy", "redmi",
                                       "poco", "oppo", "vivo", "oneplus",
                                       "huawei", "honor", "xiaomi", "moto", "nokia",
                                       "iphone", "ipad", "ipod")):
            return "Phone"
        if any(k in hostname for k in ("tv", "smarttv", "television", "tele-",
                                       "roku", "firetv", "fire-tv", "chromecast",
                                       "googletv", "androidtv", "android-tv",
                                       "mi-tv", "hisense", "tcl-", "vizio",
                                       "skyworth", "vestel", "philips", "panasonic",
                                       "samsung-", "lg-")):
            return "Smart TV"
        if any(k in hostname for k in ("laptop", "desktop", "-pc", "thinkpad",
                                       "optiplex", "elitedesk", "inspiron", "xps",
                                       "pavilion", "zenbook", "surface", "vaio")):
            return "Computer"

    # ── 2) Gateway position (subnet .1) — almost always the router, and it
    #    usually exposes a web admin UI on 80/443 so this MUST run before the
    #    port heuristics or the router gets labeled "Web Server/Device". ──
    parts = ip.split(".")
    if (len(parts) == 4 and parts[3] == "1" and
            parts[0] in ("192", "10", "172") and not hostname):
        return "Router"

    # ── 3) Randomized / privacy MAC → modern phone or tablet ──
    if _mac_is_randomized(mac):
        return "Phone/Tablet (MAC random)"

    # ── 3) Open-port signatures ──
    if ports:
        if ports & {631, 9100} or 515 in ports:
            return "Printer"
        if 53 in ports and (80 in ports or 443 in ports):
            return "Router"
        if ports & {8008, 8009, 8443, 8060, 7000, 9080, 9000}:
            return "Smart TV"
        if 445 in ports or 139 in ports or 3389 in ports:
            return "Windows PC"
        if 62078 in ports:
            return "iPhone"
        if 5555 in ports:
            return "Android Phone"
        if 22 in ports:
            return "Linux/Unix Device"
        if 80 in ports or 443 in ports:
            return "Web Server/Device"

    # ── 4) MAC-vendor category (only meaningful when the MAC is real) ──
    if vendor and vendor != "unknown":
        routers = {"tp-link", "netgear", "linksys", "d-link", "zyxel", "ubiquiti",
                   "mikrotik", "tenda", "mercusys", "totolink", "cisco"}
        tvs = {"samsung", "lg", "sony", "philips", "tcl", "xiaomi", "hisense",
               "sharp", "vizio", "panasonic", "toshiba", "roku"}
        mobile = {"apple", "samsung", "xiaomi", "huawei", "oneplus", "google",
                  "lg", "sony", "nokia", "motorola", "honor", "oppo", "vivo"}
        pcs = {"intel", "dell", "hp", "lenovo", "ibm", "microsoft", "acer",
               "asus", "toshiba", "vaio"}
        if vendor in routers:
            return "Router"
        if vendor in tvs:
            return f"{vendor.title()} TV"
        if vendor in mobile:
            return f"{vendor.title()} Phone"
        if vendor in pcs:
            return f"{vendor.title()} Computer"
        return f"{vendor.title()} Device"

    return "Unknown"


def scan_ports_batch(devices, ports=[22, 80, 443, 3389, 8080], timeout=0.3):
    """Scan common ports on multiple devices in parallel for OS fingerprinting."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _scan_one(ip):
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return ip, open_ports

    ips = [d["ip"] for d in devices if d["device_type"] == "Unknown"]
    if not ips:
        return

    print(f"[*] Scanning ports on {len(ips)} devices ({len(ports)} ports, {timeout}s timeout)...")
    with ThreadPoolExecutor(max_workers=min(50, len(ips))) as ex:
        futs = {ex.submit(_scan_one, ip): ip for ip in ips}
        for f in as_completed(futs):
            ip, open_ports = f.result()
            if open_ports:
                # Record ports only — device-type classification happens in the
                # enrichment loop via classify_device (single source of truth).
                for d in devices:
                    if d["ip"] == ip:
                        d["ports"] = open_ports
                        print(f"   {ip}: ports={open_ports}")
                        break


def discover_local_devices_win(sweep=True):
    """Discover local network devices on Windows.

    Strategy (ordered for speed + correctness):
      1. Restrict to the PRIMARY subnet (the one carrying the default route)
         so virtual adapters (Docker/VMware/WSL) and stale interfaces never
         pollute the list with wrong IPs.
      2. Warm the ARP cache with a broadcast ping and read it BEFORE the
         sweep — ARP entries are ground truth and appear in <1s.
      3. Fast ping sweep to catch ICMP-reachable hosts not yet in ARP.
      4. Re-read ARP after the sweep and merge.
    Returns a list of device dicts (ip, mac, vendor, hostname, device_type, ports)."""
    subnets = get_windows_subnets()
    if not subnets:
        subnets = [get_local_subnet()]
    gateway_ip = get_default_gateway_windows()
    primary = get_primary_subnet(subnets, gateway_ip)
    if primary:
        subnets = [primary]

    arp_entries = []
    active_ips = []
    if sweep:
        # 1. Warm the ARP cache first so enrichment sees every device
        print("[*] Sending broadcast ping to populate ARP cache...")
        broadcast_ping(subnets)
        time.sleep(0.5)
        arp_entries = parse_arp_table()
        print(f"[*] Warm ARP cache: {len(arp_entries)} entries")

        # 2. Fast ping sweep to catch ICMP-reachable hosts
        for subnet in subnets:
            active_ips.extend(ping_sweep(subnet))
        active_ips = list(dict.fromkeys(active_ips))

        # 3. Re-read ARP after the sweep and merge (dedup by IP)
        arp_entries_2 = parse_arp_table()
        seen_arp_ips = {e["ip"] for e in arp_entries}
        for e in arp_entries_2:
            if e["ip"] not in seen_arp_ips:
                arp_entries.append(e)

    arp_lookup = {e["ip"]: e for e in arp_entries}

    # ARP is ground truth: build the device list from ARP, then sweep results
    devices = []
    seen_ips = set()

    def _add(ip, mac, vendor, hostname):
        if ip in seen_ips or is_bad_network_ip(ip):
            return
        seen_ips.add(ip)
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor or "Unknown",
            "hostname": hostname, "device_type": "Unknown",
            "ports": [], "trace_route": []
        })

    for e in arp_entries:
        _add(e["ip"], e.get("mac"), e.get("vendor") or "Unknown", e.get("hostname"))
    for ip in active_ips:
        arp = arp_lookup.get(ip, {})
        _add(ip, arp.get("mac"), arp.get("vendor") or "Unknown", arp.get("hostname"))

    # Light TCP sweep on the primary subnet: catch ICMP+ARP-blocking devices
    tcp_added = 0
    for subnet in subnets:
        for ip in tcp_sweep(subnet, ports=(80, 443), timeout=0.2):
            if ip not in seen_ips and not is_broadcast_or_network(ip):
                _add(ip, None, "Unknown", None)
                tcp_added += 1
    if tcp_added:
        print(f"[*] TCP sweep added {tcp_added} devices")

    if not devices:
        print("[!] No devices found via ping sweep, ARP, or TCP probe")
        return []

    print(f"[*] Found {len(devices)} active devices — enriching with hostnames and port scans...")

    # Enrich hostnames in parallel — nbtstat is ~3s/device and was the
    # dominant bottleneck (sequential loop = tens of seconds on a real LAN)
    from concurrent.futures import ThreadPoolExecutor
    def _resolve(d):
        if not d.get("hostname"):
            name = resolve_hostname_win(d["ip"])
            if name:
                d["hostname"] = name
                print(f"   {d['ip']} -> hostname: {name}")
        return d
    with ThreadPoolExecutor(max_workers=min(16, len(devices))) as ex:
        list(ex.map(_resolve, devices))

    # Parallel port scan for device type detection
    scan_ports_batch(devices)

    # Detect local machine's own IP via the routing table (gethostbyname can
    # return a virtual/APIPA adapter address on multi-homed machines)
    self_ip = get_interface_for_destination("8.8.8.8")
    if not self_ip:
        try:
            self_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            self_ip = None

    # Classify every device with the enhanced detector (hostname + MAC +
    # ports + vendor). The machine running the copilot keeps its own label.
    for d in devices:
        if self_ip and d["ip"] == self_ip:
            d["device_type"] = "Copilot Host"
            d["vendor"] = "Self"
            print(f"   {d['ip']} -> local machine (this computer)")
            continue

        if _mac_is_randomized(d.get("mac")):
            d["vendor"] = "Private Addr"
        new_type = classify_device(d)
        if new_type != d.get("device_type"):
            print(f"   {d['ip']} -> {new_type} (ports={d.get('ports') or []})")
            d["device_type"] = new_type

    print(f"[*] Discovery complete: {len(devices)} devices")
    for d in devices:
        mac = d.get('mac') or '??'
        hostname = (d.get('hostname') or '')[:20]
        print(f"   {d['ip']:15}  {mac:18}  {d['vendor']:12}  {d['device_type']:20}  {hostname}")
    return devices


def _parse_neighbour_table():
    """Read the kernel ARP/neighbour table on Linux (no root needed).
    Returns {ip: mac} for entries with a resolved MAC address."""
    table = {}
    try:
        out = subprocess.run(['ip', '-4', 'neigh', 'show'],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if 'lladdr' in parts and parts[-1] not in ('FAILED', 'INCOMPLETE'):
                table[parts[0]] = parts[parts.index('lladdr') + 1].lower()
    except Exception:
        pass
    if not table:
        try:
            with open('/proc/net/arp') as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) >= 4 and f[3] != '00:00:00:00:00:00':
                        table[f[0]] = f[3].lower()
        except Exception:
            pass
    return table


def ping_sweep_linux(subnet, timeout_s=1, max_workers=64):
    """Parallel ping sweep using Linux ping flags. Returns IPs that answered."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    net = ipaddress.ip_network(subnet, strict=False)

    def _ping(ip):
        try:
            r = subprocess.run(['ping', '-c', '1', '-W', str(timeout_s), ip],
                               capture_output=True, timeout=timeout_s + 1)
            return ip if r.returncode == 0 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return [ip for ip in ex.map(_ping, [str(h) for h in net.hosts()]) if ip]


def discover_local_devices_linux():
    """Linux/macOS discovery that needs NO root: a ping sweep wakes devices up,
    then the kernel neighbour table gives their MAC addresses.
    Only ever returns devices that really answered on the local network."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    self_ip = get_interface_for_destination("8.8.8.8")
    try:
        net = ipaddress.ip_network(get_local_subnet(), strict=False)
        if net.prefixlen < 24 and self_ip:        # never sweep a huge /16
            net = ipaddress.ip_network(f"{self_ip}/24", strict=False)
    except ValueError:
        return []
    print(f"[*] Discovering devices on {net} (ping sweep + neighbour table, no root needed)...")
    ips = set(ping_sweep_linux(str(net)))
    neigh = _parse_neighbour_table()
    for ip in neigh:
        try:
            if ipaddress.ip_address(ip) in net:
                ips.add(ip)
        except ValueError:
            pass
    ips = {ip for ip in ips if ip != self_ip and not is_bad_network_ip(ip)}

    def _enrich(ip):
        mac = neigh.get(ip)
        vendor = mac_vendor_lookup(mac) if mac else "Unknown"
        hostname = get_hostname(ip)
        ports = scan_ports(ip, timeout=0.5)
        dtype = classify_device({"ip": ip, "mac": mac, "vendor": vendor,
                                 "hostname": hostname, "ports": ports})
        return {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
                "device_type": dtype, "ports": ports, "trace_route": []}

    with ThreadPoolExecutor(max_workers=16) as ex:
        devices = list(ex.map(_enrich, sorted(ips, key=ipaddress.ip_address)))
    print(f"[*] Discovery complete: {len(devices)} devices")
    return devices


def _parse_arp_table_linux():
    """Linux/macOS version of parse_arp_table(): read the kernel neighbour table."""
    devices = []
    for ip, mac in _parse_neighbour_table().items():
        if is_bad_network_ip(ip):
            continue
        devices.append({
            "ip": ip, "mac": mac, "vendor": mac_vendor_lookup(mac),
            "hostname": None, "device_type": "Unknown",
            "ports": [], "trace_route": []
        })
    return devices


def _wake_neighbours_linux():
    """Linux equivalent of broadcast_ping(): ping the local /24 so that devices
    that joined since the last scan show up in the neighbour table."""
    import ipaddress
    try:
        self_ip = get_interface_for_destination("8.8.8.8")
        net = ipaddress.ip_network(get_local_subnet(), strict=False)
        if net.prefixlen < 24 and self_ip:
            net = ipaddress.ip_network(f"{self_ip}/24", strict=False)
        ping_sweep_linux(str(net))
    except Exception:
        pass


def _fallback_discovery():
    """Used when the raw ARP scan is unavailable (not root, no scapy, empty result).
    NEVER falls back to hosts.txt: public hosts such as 8.8.8.8 or google.com
    are not devices on your network and would pollute the dashboard."""
    if sys.platform == "win32":
        return discover_local_devices_win()
    return discover_local_devices_linux()


def discover_network_devices(subnet=None):
    """
    Discover network devices with enhanced information.
    Returns a list of dictionaries with device information.
    """
    if not SCAPY_AVAILABLE:
        print("[!] scapy not available; using ping sweep + neighbour table")
        return _fallback_discovery()

    # Auto-detect subnet if not provided
    if subnet is None:
        subnet = get_local_subnet()
        print(f"[*] Auto-detected subnet: {subnet}")

    print(f"[*] Discovering devices on subnet {subnet}...")

    # Perform ARP scan — pin interface to avoid loopback adapter error
    conf.iface = get_scapy_iface()
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        result = srp(packet, iface=get_scapy_iface(), timeout=5, inter=0.1, verbose=0)[0]
    except Exception as e:
        print(f"[!] ARP scan failed ({e}). Raw ARP needs root; "
              f"using ping sweep + neighbour table instead.")
        return _fallback_discovery()

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        # Get basic information
        vendor = mac_vendor_lookup(mac)
        hostname = get_hostname(ip)
        ports = scan_ports(ip, timeout=0.5)  # Quick scan
        device_type = classify_device({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "ports": ports
        })
        trace_route = traceroute(ip, max_hops=5)  # Limited traceroute

        # Get SNMP information if available
        snmp_info = {}
        if SNMP_AVAILABLE:
            try:
                # Try to get system information via SNMP
                snmp_info = snmp_get_system_info(ip)

                # If we got sysDescr, try to get more detailed info
                if 'sysDescr' in snmp_info:
                    # Try to get interface information
                    interfaces = snmp_get_interfaces(ip)
                    if interfaces:
                        snmp_info['interfaces'] = interfaces

            except Exception as e:
                # Silently continue if SNMP fails
                pass

        device_info = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "device_type": device_type,
            "ports": ports,
            "trace_route": trace_route,
            "last_seen": datetime.datetime.now().isoformat(),
            "snmp_info": snmp_info
        }

        devices.append(device_info)
        print(f"[+] Found device: {ip} ({mac}) - {vendor} - {device_type}")
        if snmp_info:
            # Get a description for display
            descr = "N/A"
            if 'system' in snmp_info and 'sysDescr' in snmp_info['system']:
                descr = snmp_info['system']['sysDescr']
            elif 'sysDescr' in snmp_info:
                descr = snmp_info['sysDescr']
            print(f"    SNMP Info: {descr[:50]}...")

    if not devices:
        print("[!] No devices found via ARP; trying ping sweep + neighbour table")
        return _fallback_discovery()

    return devices


def ping_host(host, timeout_ms=800):
    """
    Ping a host using subprocess ping with encoding-safe parsing.
    Returns (latency_ms, success).
    """
    try:
        if sys.platform == "win32":
            cmd = ['ping', '-n', '1', '-w', str(timeout_ms), host]
            cmd_timeout = timeout_ms // 1000 + 2
        else:
            timeout_s = max(1, int(timeout_ms / 1000))
            cmd = ['ping', '-c', '1', '-W', str(timeout_s), host]
            cmd_timeout = timeout_s + 2
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=cmd_timeout
        )
        if proc.returncode != 0:
            return None, False

        raw = proc.stdout
        # Try multiple encodings (Windows locale can mangle text=True)
        for enc in ('utf-8', 'cp1252', 'cp850', 'latin-1'):
            try:
                text = raw.decode(enc, errors='replace')
                # Match any number followed by "ms" — handles all locales
                m = re.search(r'[=<>](\d+\.?\d*)\s*ms', text, re.IGNORECASE)
                if m:
                    return float(m.group(1)), True
            except Exception:
                continue

        # ping succeeded (returncode 0) but latency regex failed — locale edge case
        # Return a minimal latency so real data flows instead of simulated
        return 0.1, True
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
        is_anomaly = 1 if detecter_anomalie_seuils_adaptatifs(latency, error_rate, host) else 0
        print(f"[INFO] {host}: latency={latency:.2f} ms")
    else:
        # Host did not answer the ping — do NOT fabricate a metric for it.
        # Returning None means no row is written, so offline devices drop out
        # of the topology automatically (live detection) instead of lingering
        # forever on simulated data.
        print(f"[WARN] {host}: ping failed — host offline, no metric written")
        return None

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


def discover_hosts(subnet="192.168.1.0/24", timeout=2):
    """
    Discover active hosts on the local network using ARP scanning.
    Returns a list of tuples (ip, mac) for hosts that responded.
    Requires scapy.
    """
    if not SCAPY_AVAILABLE:
        print("Scapy not available; falling back to hosts.txt")
        # Return list of (ip, None) for hosts from file
        return [(ip, None) for ip in load_hosts_from_file()]

    print(f"[*] Scanning network {subnet} for active hosts (ARP scan)...")
    # Suppress scapy verbose output
    conf.verb = 0

    # Create ARP request packet — pin interface to avoid loopback adapter error
    conf.iface = get_scapy_iface()
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and capture responses
    try:
        result = srp(packet, iface=get_scapy_iface(), timeout=max(timeout,5), inter=0.1, verbose=0)[0]
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        return [(ip, None) for ip in load_hosts_from_file()]

    hosts = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        hosts.append((ip, mac))
        print(f"[+] Found host: {ip} ({mac})")

    if not hosts:
        print("[!] No hosts discovered via ARP; falling back to hosts.txt")
        return [(ip, None) for ip in load_hosts_from_file()]
    return hosts


def sauvegarder(metrique, mac=None):
    """
    Save a metric to the database
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO network_metrics
        (ts, host, latency, error_rate, traffic, is_anomaly, mac)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        metrique["ts"],
        metrique["host"],
        metrique["latency"],
        metrique["error_rate"],
        metrique["traffic"],
        metrique["is_anomaly"],
        mac
    ))

    conn.commit()
    conn.close()


def sauvegarder_batch(rows):
    """Insert multiple (metrique, mac) rows in a single transaction.

    Rows is a list of (metrique_dict, mac) tuples, as produced by the
    parallel ping cycle. One connection + executemany is far cheaper than
    opening a sqlite connection per metric."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO network_metrics
        (ts, host, latency, error_rate, traffic, is_anomaly, mac)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [(
        m["ts"], m["host"], m["latency"], m["error_rate"],
        m["traffic"], m["is_anomaly"], mac
    ) for m, mac in rows])
    conn.commit()
    conn.close()


def sauvegarder_proprietes_appareil(ip_address, properties):
    """
    Save device properties to the database
    """
    _API_DATABASE.save_device_properties(ip_address, properties)


def main():
    parser = argparse.ArgumentParser(description="Network monitor simulator")
    parser.add_argument("--use-file", action="store_true", help="Force using hosts.txt instead of discovery")
    parser.add_argument("--interval", type=int, default=10, help="Seconds between polling cycles (default: 10 seconds)")
    parser.add_argument("--rediscover-interval", type=int, default=300, help="Seconds between network rediscovery (default: 300 = 5 minutes)")
    args = parser.parse_args()

    # On crée la base de données si elle n'existe pas
    creer_base_de_donnees()

    # Initialize device tracking
    known_devices = {}  # IP -> device_info
    offline_streak = {}  # IP -> consecutive failed ping cycles
    last_discovery_time = 0

    print(f"[INFO] Network Monitor started !")
    print(f"[INFO] Polling interval: {args.interval}s")
    print(f"[INFO] Rediscovery interval: {args.rediscover_interval}s")
    print("Press Ctrl+C to stop\n")

    compteur = 0

    try:
        while True:
            compteur += 1
            current_time = time.time()
            print(f"--- Cycle #{compteur} ---")

            # Perform network discovery if it's time or if we have no known devices
            if (current_time - last_discovery_time >= args.rediscover_interval) or not known_devices:
                print("[INFO] Performing network discovery...")
                if args.use_file:
                    # Force file-based discovery
                    hosts_file = os.path.join(os.path.dirname(__file__), "hosts.txt")
                    host_ips = load_hosts_from_file(hosts_file)
                    devices = [{"ip": ip, "mac": None, "vendor": "Unknown", "hostname": None,
                               "device_type": "Unknown", "ports": [], "trace_route": []}
                               for ip in host_ips]
                    print(f"[INFO] Loaded {len(host_ips)} hosts from {hosts_file}")
                elif SCAPY_AVAILABLE and sys.platform != "win32":
                    # Scapy ARP scan (Linux/Mac only — broken loopback adapter on Windows)
                    devices = discover_network_devices()
                else:
                    # Windows: ping sweep + ARP cache (reliable, no admin needed)
                    devices = discover_local_devices_win()
                    if not devices:
                        # NOTE: intentionally NOT falling back to hosts.txt — seeding
                        # public IPs (8.8.8.8, google.com...) would show wrong devices
                        # on the dashboard. self + gateway are added right below, so
                        # monitoring always has real hosts.
                        print("[WARN] Discovery returned no devices — monitoring self + gateway only")

                # ── Dynamically add self + gateway ──────
                self_ip = get_interface_for_destination("8.8.8.8")
                if not self_ip:
                    try:
                        self_ip = socket.gethostbyname(socket.gethostname())
                    except Exception:
                        self_ip = None
                gateway_ip = (get_default_gateway_windows() if sys.platform == "win32"
                              else get_default_gateway_linux())
                existing_ips = {d["ip"] for d in devices}
                if self_ip and self_ip not in existing_ips:
                    devices.append({
                        "ip": self_ip, "mac": None,
                        "vendor": "Self", "hostname": socket.gethostname(),
                        "device_type": "Copilot Host", "ports": [8000, 8501], "trace_route": []
                    })
                    print(f"[+] Added self: {self_ip}")
                if gateway_ip:
                    if gateway_ip not in existing_ips:
                        devices.append({
                            "ip": gateway_ip, "mac": None,
                            "vendor": "Gateway", "hostname": "gateway",
                            "device_type": "Router", "ports": [], "trace_route": []
                        })
                        print(f"[+] Added gateway: {gateway_ip}")
                    else:
                        # The gateway was auto-discovered and typed "Web Server"
                        # (router admin UI opens 80/443). Force the correct type —
                        # properties are saved with the others below.
                        for d in devices:
                            if d["ip"] == gateway_ip:
                                d["vendor"] = d.get("vendor") or "Gateway"
                                d["hostname"] = d.get("hostname") or "gateway"
                                d["device_type"] = "Router"
                                print(f"[+] Gateway {gateway_ip} typed as Router")
                                break

                # Update known devices
                new_devices = []
                current_ips = set()
                for device in devices:
                    ip = device["ip"]
                    current_ips.add(ip)
                    if ip not in known_devices:
                        new_devices.append(device)
                        print(f"[INFO] New device discovered: {ip} ({device.get('mac', 'N/A')}) - {device['vendor']} - {device['device_type']}")
                    else:
                        # Update existing device information
                        known_devices[ip].update(device)

                # MAC-stable identity: if a known device reappears under a new IP
                # (DHCP re-assignment) and its old IP is no longer on the network,
                # follow the MAC instead of showing a stale duplicate.
                mac_to_ip = {d.get("mac"): d["ip"] for d in devices if d.get("mac")}
                for mac, new_ip in mac_to_ip.items():
                    for old_ip, info in list(known_devices.items()):
                        if (info.get("mac") == mac and old_ip != new_ip
                                and old_ip not in current_ips and new_ip in current_ips):
                            print(f"[INFO] Device {mac} moved IP {old_ip} -> {new_ip}")
                            info["ip"] = new_ip
                            known_devices[new_ip] = info
                            del known_devices[old_ip]

                # Add new devices to known devices and save their properties
                current_ips = []
                for device in devices:
                    known_devices[device["ip"]] = device
                    current_ips.append(device["ip"])
                    # Save device properties to database
                    properties = {
                        "vendor": device.get("vendor"),
                        "hostname": device.get("hostname"),
                        "device_type": device.get("device_type"),
                        "ports": device.get("ports", []),
                        "snmp_info": device.get("snmp_info", {})
                    }
                    # Filter out None values
                    properties = {k: v for k, v in properties.items() if v is not None}
                    sauvegarder_proprietes_appareil(device["ip"], properties)

                # Remove stale devices from database (no longer on network)
                _API_DATABASE.cleanup_stale_devices(current_ips)

                last_discovery_time = current_time
                print(f"[SUCCESS] Discovery complete. Monitoring {len(known_devices)} devices.")
                # Cool-down delay after ping sweep to let ICMP rate-limiting expire
                time.sleep(2)

            # ── Mini-discovery (every ~60s): broadcast ping + ARP cache for new devices ──
            # Gated so we don't spawn a PowerShell process every 10s cycle.
            if time.time() - getattr(main, "_last_mini_discovery", 0) >= 60:
                main._last_mini_discovery = time.time()
                try:
                    if sys.platform == "win32":
                        broadcast_ping()
                    else:
                        _wake_neighbours_linux()
                    time.sleep(0.3)
                    new_arp = parse_arp_table()
                    for d in new_arp:
                        ip = d["ip"]
                        if ip not in known_devices and not is_broadcast_or_network(ip):
                            # Classify BEFORE saving — previously this path saved
                            # a hardcoded "Unknown", which is why some phones
                            # (e.g. .16) showed up as generic nodes.
                            if _mac_is_randomized(d.get("mac")):
                                d["vendor"] = "Private Addr"
                            known_devices[ip] = d
                            sauvegarder_proprietes_appareil(ip, {
                                "vendor": d.get("vendor", "Unknown"),
                                "hostname": d.get("hostname"),
                                "device_type": classify_device(d),
                                "ports": d.get("ports") or [],
                                "snmp_info": {}
                            })
                            print(f"[INFO] New device detected via ARP (between cycles): {ip}")
                except Exception:
                    pass

            # NOTE: the old "recover hosts from DB" block is intentionally gone.
            # It re-added ANY host seen in the last 30 minutes to the monitoring
            # list — including devices that were no longer on the network — which
            # is exactly why offline devices kept appearing in the topology.
            # Discovery + ARP are the ONLY source of truth now (live detection).

            # Prepare hosts for monitoring (IP and MAC pairs)
            hosts_to_monitor = [(device["ip"], device.get("mac")) for device in known_devices.values()]

            if not hosts_to_monitor:
                print("❌ No hosts to monitor. Waiting for next discovery cycle...")
                print()  # Blank line between cycles
                time.sleep(args.interval)
                continue

            # Extract just the IPs for printing
            hosts = [device["ip"] for device in known_devices.values()]
            print(f"[INFO] Monitoring {len(hosts)} devices: {', '.join(hosts[:5])}{'...' if len(hosts) > 5 else ''}")

            # Ping ALL hosts in parallel, then write all metrics in ONE batch insert
            # (avoiding N separate sqlite connections per cycle)
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def _ping(host_mac):
                host, mac = host_mac
                metrique = generate_metrique_for_host(host)
                return host, metrique is not None, metrique, mac

            rows = []
            results = []
            with ThreadPoolExecutor(max_workers=min(20, len(hosts_to_monitor))) as ex:
                futs = {ex.submit(_ping, hm): hm for hm in hosts_to_monitor}
                for f in as_completed(futs):
                    host, ok, metrique, mac = f.result()
                    results.append((host, ok))
                    if ok and metrique is not None:
                        rows.append((metrique, mac))
                    else:
                        print(f"   {host}: ping failed")
            if rows:
                sauvegarder_batch(rows)
            ok_count = sum(1 for _, ok in results if ok)
            fail_count = len(results) - ok_count
            print(f"[CYCLE] Pinged {len(results)} hosts: {ok_count} OK, {fail_count} failed")

            # Wi-Fi power-save: phones/TVs sleep for tens of seconds without
            # answering pings, so DON'T drop after a few failures — they just
            # vanish from the topology (via the dashboard's liveness window)
            # and reappear the instant they answer again. Only drop after a
            # long streak (~2.5 min at 10s cycles); the full rediscovery prunes
            # devices that are truly gone.
            for host, ok in results:
                if ok:
                    offline_streak.pop(host, None)
                else:
                    offline_streak[host] = offline_streak.get(host, 0) + 1
            for host, streak in list(offline_streak.items()):
                if streak >= 15:
                    print(f"[INFO] {host} offline for {streak} cycles — removing from monitoring")
                    known_devices.pop(host, None)
                    offline_streak.pop(host, None)

            print()  # Blank line between cycles

            # Wait before next cycle
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n🛑 Network Monitor arrêté par l'utilisateur.")


if __name__ == "__main__":
    main()
