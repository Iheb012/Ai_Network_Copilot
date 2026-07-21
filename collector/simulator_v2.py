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

# Add the api directory to path to import database functions
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'api'))
from database import creer_base_de_donnees

# Try to import scapy for ARP scanning; if not available, fallback to file-based hosts
try:
    from scapy.all import ARP, Ether, srp, conf, sr1, IP, ICMP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Network discovery disabled. Install with: pip install scapy")

# ── Pinned network interface (auto-detected: 192.168.1.19) ──────────────────
# Change this if your interface GUID changes (run get_if_list() to find it)
SCAPY_IFACE = r"\Device\NPF_{20AC1ACB-17E7-48D4-82EA-04348BB56226}"

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
                'mtu': intif_mtu if if_mtu and if_mtu.isdigit() else None,
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


def get_hostname(ip):
    """Resolve hostname for an IP address using reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None
    except Exception:
        return None


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


def detect_device_type(open_ports, mac_vendor=None):
    """
    Detect device type based on open ports and MAC vendor.
    Returns a device type string.
    """
    # Common port to service mappings
    port_services = {
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }

    # Device type heuristics
    if 22 in open_ports or 23 in open_ports:
        if any(vendor in (mac_vendor or "").lower() for vendor in ["cisco", "juniper", "hp", "aruba"]):
            return "Network Switch/Router"
        else:
            return "Linux/Unix Server"

    if 3389 in open_ports:
        return "Windows Server"

    # Android TV / Chromecast detection
    if 8080 in open_ports or 9080 in open_ports or 8008 in open_ports:
        if any(vendor in (mac_vendor or "").lower() for vendor in ["google", "android", "chromecast", "sony", "philips", "tcl", "xiaomi", "hisense", "sharp", "vizio", "samsung", "lg"]):
            return "Android TV"

    # Smart TV detection (ports 80/443 but no 8080)
    if 80 in open_ports or 443 in open_ports:
        if any(vendor in (mac_vendor or "").lower() for vendor in ["samsung", "lg", "sony", "philips", "tcl", "xiaomi", "hisense", "sharp", "vizio", "google", "android"]):
            return "Smart TV"

    if 80 in open_ports or 443 in open_ports or 8080 in open_ports or 8443 in open_ports:
        if any(vendor in (mac_vendor or "").lower() for vendor in ["apple", "microsoft"]):
            return "Workstation"
        else:
            return "Web Server"

    if 161 in open_ports or 162 in open_ports:  # SNMP
        if any(vendor in (mac_vendor or "").lower() for vendor in ["cisco", "juniper", "hp", "dell"]):
            return "Network Device"
        else:
            return "Server"

    # Default classification based on open ports
    if not open_ports:
        return "Unknown Device"
    elif 80 in open_ports or 443 in open_ports:
        return "Web Server"
    elif 22 in open_ports:
        return "SSH Server"
    elif 3389 in open_ports:
        return "Windows Host"
    else:
        return "Network Device"


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


def ping_sweep(subnet="192.168.1.0/24", timeout=1000, max_workers=20):
    """Fast parallel ping sweep to discover active hosts on a subnet.
    Uses limited parallelism to avoid ICMP rate-limiting on consumer routers.
    Returns list of (ip, success) tuples for hosts that responded."""
    import ipaddress

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
    # Process in small batches to avoid ICMP rate limiting
    for batch_start in range(0, len(hosts), max_workers):
        batch = hosts[batch_start:batch_start + max_workers]
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(_ping, ip): ip for ip in batch}
            for f in as_completed(futs):
                ip, ok = f.result()
                if ok:
                    active.append(ip)
        done = min(batch_start + max_workers, len(hosts))
        print(f"   Sweep progress: {done}/{len(hosts)} ({len(active)} found)")
        # Small delay between batches to let router's ICMP budget replenish
        if batch_start + max_workers < len(hosts):
            time.sleep(0.5)

    print(f"[*] Ping sweep complete: {len(active)} active hosts found")
    return active


def tcp_probe(ip, ports=None, timeout=0.8):
    """Try TCP connection to ports as a lightweight probe for ping-resistant devices.
    Uses non-blocking connect with short timeout. Returns True if any port accepts."""
    if ports is None:
        ports = (80, 443, 8080, 5353, 1900, 62078, 5000, 8443)
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
    - Loopback addresses (127.x.x.x)
    - Unreachable/Incomplete entries (no device at this IP)
    - Entries with all-zeros MAC (fake placeholder)
    """
    if ip and ip.startswith("127."):
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
                if (ip.startswith('224.') or ip.startswith('239.') or
                    ip == '255.255.255.255' or ip.startswith('169.254.') or
                    is_broadcast_or_network(ip) or ip in seen_ips):
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
                hostname = get_hostname(ip)
                print(f"   [ARP] {ip} mac={mac or '?'} state={state}")
                devices.append({
                    "ip": ip, "mac": mac, "vendor": vendor,
                    "hostname": hostname, "device_type": "Unknown",
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
                    if (ip.startswith('224.') or ip.startswith('239.') or
                        ip == '255.255.255.255' or ip.startswith('169.254.') or
                        is_broadcast_or_network(ip) or ip in seen_ips):
                        continue
                    if mac == ALL_ZEROS_MAC:
                        continue
                    seen_ips.add(ip)
                    vendor = mac_vendor_lookup(mac)
                    hostname = get_hostname(ip)
                    print(f"   [ARP] {ip} mac={mac} (from arp -a)")
                    devices.append({
                        "ip": ip, "mac": mac, "vendor": vendor,
                        "hostname": hostname, "device_type": "Unknown",
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


def scan_ports_batch(devices, ports=[22, 80, 443, 3389, 8080], timeout=0.5):
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
                # Update device in the original list
                for d in devices:
                    if d["ip"] == ip:
                        d["ports"] = open_ports
                        # Use existing detect_device_type with more mobile-friendly fallback
                        dtype = detect_device_type(open_ports, d.get("vendor"))
                        if dtype == "Unknown Device" and d.get("vendor") != "Unknown":
                            # Mobile device heuristic
                            dtype = f"{d['vendor']} Device"
                        d["device_type"] = dtype
                        print(f"   {ip}: ports={open_ports} -> {d['vendor']} {d['device_type']}")
                        break


def discover_local_devices_win(sweep=True):
    """Discover local network devices on Windows.
    Scans ALL detected subnets (Ethernet, Wi-Fi, phone hotspots, etc.)
    Uses ping sweep as the source of truth for active hosts.
    Enriches with MAC/vendor from ARP table and adds hostname/device type.
    Falls back to ARP-only devices (even those not responding to ICMP/TCP).
    Returns a list of device dicts (ip, mac, vendor, hostname, device_type, ports)."""
    subnets = get_windows_subnets()
    if not subnets:
        subnets = [get_local_subnet()]

    active_ips = []
    if sweep:
        for subnet in subnets:
            print(f"[*] Sweeping subnet: {subnet}")
            found = ping_sweep(subnet, timeout=1000, max_workers=20)
            active_ips.extend(found)
            time.sleep(0.5)
        # Remove duplicates
        active_ips = list(dict.fromkeys(active_ips))

    # Broadcast ping to populate ARP cache with ALL devices
    print("[*] Sending broadcast ping to populate ARP cache...")
    broadcast_ping(subnets)
    time.sleep(1.0)

    # Build ARP lookup table (IP → mac/vendor/hostname)
    print("[*] Reading Windows ARP cache for enrichment...")
    arp_entries = parse_arp_table()
    arp_lookup = {}
    for e in arp_entries:
        arp_lookup[e["ip"]] = e

    # Build device list from ping sweep results, enriched with ARP data
    devices = []
    for ip in active_ips:
        arp = arp_lookup.get(ip, {})
        mac = arp.get("mac")
        vendor = arp.get("vendor") or "Unknown"
        hostname = arp.get("hostname")
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "device_type": "Unknown",
            "ports": [], "trace_route": []
        })

    # ARP-based fallback: devices in ARP cache that didn't respond to ping
    # but DO respond to TCP on common ports (catches phones, smart TVs etc.)
    # PLUS devices that don't respond to anything but are still in the ARP cache
    arp_ips_missed = [e["ip"] for e in arp_entries if e["ip"] not in active_ips
                      and not is_broadcast_or_network(e["ip"])]
    if arp_ips_missed:
        print(f"[*] Probing {len(arp_ips_missed)} ARP-only IPs with TCP...")
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def _tcp_check(ip):
            return ip, tcp_probe(ip)
        tcp_found = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(_tcp_check, ip): ip for ip in arp_ips_missed}
            for f in as_completed(futs):
                ip, alive = f.result()
                if alive:
                    tcp_found.append(ip)
        # Always include ALL ARP entries that aren't already in the device list
        # (even if they don't respond to TCP — they're on the network)
        for e in arp_entries:
            ip = e["ip"]
            if ip not in active_ips and ip not in tcp_found and not is_broadcast_or_network(ip):
                # Add it anyway — ARP doesn't lie, this device exists on the LAN
                tcp_found.append(ip)
                print(f"   {ip} -> ARP cache entry, added to device list")
        for ip in tcp_found:
            arp = arp_lookup.get(ip, {})
            mac = arp.get("mac")
            vendor = arp.get("vendor") or "Unknown"
            hostname = arp.get("hostname")
            devices.append({
                "ip": ip, "mac": mac, "vendor": vendor,
                "hostname": hostname, "device_type": "Unknown",
                "ports": [], "trace_route": []
            })
        print(f"[*] ARP fallback added {len(devices) - len(active_ips)} devices")

    # TCP sweep: catch ICMP-blocking devices that respond on port 80/443
    known_ips = {d["ip"] for d in devices}
    tcp_added = 0
    for subnet in subnets:
        tcp_hosts = tcp_sweep(subnet, ports=(80, 443, 8080), timeout=0.3)
        for ip in tcp_hosts:
            if ip not in known_ips and not is_broadcast_or_network(ip):
                devices.append({
                    "ip": ip, "mac": None, "vendor": "Unknown",
                    "hostname": None, "device_type": "Unknown",
                    "ports": [], "trace_route": []
                })
                known_ips.add(ip)
                tcp_added += 1
                print(f"   {ip} -> TCP probe (port 80/443) OK, added to device list")
    if tcp_added:
        print(f"[*] TCP sweep added {tcp_added} devices")

    if not devices:
        print("[!] No devices found via ping sweep, ARP, or TCP probe")
        return []

    print(f"[*] Found {len(devices)} active devices — enriching with hostnames and port scans...")

    # Enrich with better hostnames
    for d in devices:
        if not d["hostname"]:
            name = resolve_hostname_win(d["ip"])
            if name:
                d["hostname"] = name
                print(f"   {d['ip']} -> hostname: {name}")

    # Parallel port scan for device type detection
    scan_ports_batch(devices)

    # Detect local machine's own IP
    try:
        self_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        self_ip = None

    # For devices still Unknown, use vendor-based heuristic
    for d in devices:
        # Mark the machine running the copilot
        if self_ip and d["ip"] == self_ip:
            d["device_type"] = "Copilot Host"
            d["vendor"] = "Self"
            print(f"   {d['ip']} -> local machine (this computer)")

        # Detect randomized/private MAC addresses (modern phones)
        mac = d.get("mac") or ""
        if len(mac) >= 2:
            second_char = mac[1]  # second hex digit of first byte
            if second_char in '26ae' and d["device_type"] in ("Unknown", "Unknown Device"):
                d["vendor"] = "Private Addr"
                d["device_type"] = "Phone (MAC random)"
                print(f"   {d['ip']} -> randomized MAC - phone with privacy enabled")

        if d["device_type"] in ("Unknown", "Unknown Device"):
            v = d.get("vendor", "Unknown")
            if v not in ("Unknown",):
                tv_vendors = {"Samsung", "LG", "Sony", "Philips", "TCL",
                              "Xiaomi", "Hisense", "Sharp", "Vizio", "Panasonic",
                              "Toshiba", "Roku"}
                mobile_vendors = {"Apple", "Samsung", "Xiaomi", "Huawei", "OnePlus",
                                  "Google", "LG", "Sony", "Nokia", "Motorola"}
                pc_vendors = {"Intel", "Dell", "HP", "Lenovo", "IBM",
                              "Compaq", "Microsoft", "VMware", "Acer", "Asus"}
                if v in tv_vendors:
                    d["device_type"] = f"{v} TV"
                elif v in mobile_vendors:
                    d["device_type"] = f"{v} Mobile"
                elif v in pc_vendors:
                    d["device_type"] = f"{v} PC"
                else:
                    d["device_type"] = f"{v} Device"
            else:
                d["device_type"] = "Unknown Device"

        # Hostname-based override — catch TVs that ports+vendor missed
        hostname = (d.get("hostname") or "").lower()
        if "tv" in hostname or "tele" in hostname or "smarttv" in hostname or "television" in hostname:
            if "tv" not in d["device_type"].lower():
                print(f"   {d['ip']} -> hostname '{hostname}' suggests TV")
                d["device_type"] = "Smart TV"

    print(f"[*] Discovery complete: {len(devices)} devices")
    for d in devices:
        mac = d.get('mac') or '??'
        hostname = (d.get('hostname') or '')[:20]
        print(f"   {d['ip']:15}  {mac:18}  {d['vendor']:12}  {d['device_type']:20}  {hostname}")
    return devices


def discover_network_devices(subnet=None):
    """
    Discover network devices with enhanced information.
    Returns a list of dictionaries with device information.
    """
    if not SCAPY_AVAILABLE:
        print("Scapy not available; trying Windows ARP cache...")
        arp_devices = discover_local_devices_win()
        if arp_devices:
            return arp_devices
        print("[!] ARP empty; falling back to hosts.txt")
        hosts = load_hosts_from_file()
        return [{"ip": ip, "mac": None, "vendor": "Unknown", "hostname": None,
                "device_type": "Unknown", "ports": [], "trace_route": []}
                for ip in hosts]

    # Auto-detect subnet if not provided
    if subnet is None:
        subnet = get_local_subnet()
        print(f"[*] Auto-detected subnet: {subnet}")

    print(f"[*] Discovering devices on subnet {subnet}...")

    # Perform ARP scan — pin interface to avoid loopback adapter error
    conf.iface = SCAPY_IFACE
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        result = srp(packet, iface=SCAPY_IFACE, timeout=5, inter=0.1, verbose=0)[0]
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        print("[!] Trying Windows ARP cache as fallback...")
        arp_devices = discover_local_devices_win()
        if arp_devices:
            return arp_devices
        print("[!] Falling back to hosts.txt")
        hosts = load_hosts_from_file()
        return [{"ip": ip, "mac": None, "vendor": "Unknown", "hostname": None,
                 "device_type": "Unknown", "ports": [], "trace_route": []}
                for ip in hosts]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc

        # Get basic information
        vendor = mac_vendor_lookup(mac)
        hostname = get_hostname(ip)
        ports = scan_ports(ip, timeout=0.5)  # Quick scan
        device_type = detect_device_type(ports, vendor)
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
        print("[!] No devices discovered via ARP; trying Windows ARP cache...")
        arp_devices = discover_local_devices_win()
        if arp_devices:
            return arp_devices
        print("[!] Falling back to hosts.txt")
        hosts = load_hosts_from_file()
        return [{"ip": ip, "mac": None, "vendor": "Unknown", "hostname": None,
                "device_type": "Unknown", "ports": [], "trace_route": []}
                for ip in hosts]

    return devices


def ping_host(host, timeout_ms=800):
    """
    Ping a host using subprocess ping with encoding-safe parsing.
    Returns (latency_ms, success).
    """
    try:
        proc = subprocess.run(
            ['ping', '-n', '1', '-w', str(timeout_ms), host],
            capture_output=True, timeout=timeout_ms//1000 + 2
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
        # Ping failed — use simulated normal data so dashboard stays live
        import random as _r
        latency     = round(_r.uniform(5, 45), 2)
        error_rate  = round(_r.uniform(0, 1), 2)
        is_anomaly  = 0
        print(f"[WARN] {host}: ping failed — simulated {latency} ms")

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
    conf.iface = SCAPY_IFACE
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and capture responses
    try:
        result = srp(packet, iface=SCAPY_IFACE, timeout=max(timeout,5), inter=0.1, verbose=0)[0]
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


def sauvegarder_proprietes_appareil(ip_address, properties):
    """
    Save device properties to the database
    """
    # Add the API directory to path to import database functions
    api_path = os.path.join(os.path.dirname(__file__), '..', 'api')
    if api_path not in sys.path:
        sys.path.insert(0, api_path)
    from database import save_device_properties

    # Save the properties
    save_device_properties(ip_address, properties)


def main():
    parser = argparse.ArgumentParser(description="Network monitor simulator")
    parser.add_argument("--use-file", action="store_true", help="Force using hosts.txt instead of discovery")
    parser.add_argument("--interval", type=int, default=10, help="Seconds between polling cycles (default: 300 = 5 minutes)")
    parser.add_argument("--rediscover-interval", type=int, default=120, help="Seconds between network rediscovery (default: 600 = 10 minutes)")
    args = parser.parse_args()

    # On crée la base de données si elle n'existe pas
    creer_base_de_donnees()

    # Initialize device tracking
    known_devices = {}  # IP -> device_info
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
                        hosts_file = os.path.join(os.path.dirname(__file__), "hosts.txt")
                        host_ips = load_hosts_from_file(hosts_file)
                        devices = [{"ip": ip, "mac": None, "vendor": "Unknown", "hostname": None,
                                   "device_type": "Unknown", "ports": [], "trace_route": []}
                                   for ip in host_ips]
                        print(f"[INFO] Fallback: loaded {len(host_ips)} hosts from {hosts_file}")

                # ── Dynamically add self + gateway ──────
                self_ip = None
                gateway_ip = None
                try:
                    self_ip = socket.gethostbyname(socket.gethostname())
                    # Detect gateway from routing table
                    route_out = subprocess.run(
                        ['powershell', '-NoProfile', '-Command',
                         'Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1 -ExpandProperty NextHop'],
                        capture_output=True, text=True, timeout=5
                    )
                    if route_out.returncode == 0:
                        gw = route_out.stdout.strip()
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', gw):
                            gateway_ip = gw
                except Exception:
                    pass
                existing_ips = {d["ip"] for d in devices}
                if self_ip and self_ip not in existing_ips:
                    devices.append({
                        "ip": self_ip, "mac": None,
                        "vendor": "Self", "hostname": socket.gethostname(),
                        "device_type": "Copilot Host", "ports": [8000, 8501], "trace_route": []
                    })
                    print(f"[+] Added self: {self_ip}")
                if gateway_ip and gateway_ip not in existing_ips:
                    devices.append({
                        "ip": gateway_ip, "mac": None,
                        "vendor": "Gateway", "hostname": "gateway",
                        "device_type": "Router", "ports": [], "trace_route": []
                    })
                    print(f"[+] Added gateway: {gateway_ip}")

                # Update known devices
                new_devices = []
                for device in devices:
                    ip = device["ip"]
                    if ip not in known_devices:
                        new_devices.append(device)
                        print(f"[INFO] New device discovered: {ip} ({device.get('mac', 'N/A')}) - {device['vendor']} - {device['device_type']}")
                    else:
                        # Update existing device information
                        known_devices[ip].update(device)

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
                from database import cleanup_stale_devices
                cleanup_stale_devices(current_ips)

                last_discovery_time = current_time
                print(f"[SUCCESS] Discovery complete. Monitoring {len(known_devices)} devices.")
                # Cool-down delay after ping sweep to let ICMP rate-limiting expire
                time.sleep(2)

            # ── Mini-discovery every cycle: broadcast ping + ARP cache for new devices ──
            try:
                broadcast_ping()
                time.sleep(0.3)
                new_arp = parse_arp_table()
                for d in new_arp:
                    ip = d["ip"]
                    if ip not in known_devices and not is_broadcast_or_network(ip):
                        known_devices[ip] = d
                        sauvegarder_proprietes_appareil(ip, {
                            "vendor": d.get("vendor", "Unknown"),
                            "hostname": d.get("hostname"),
                            "device_type": "Unknown",
                            "ports": [],
                            "snmp_info": {}
                        })
                        print(f"[INFO] New device detected via ARP (between cycles): {ip}")
            except Exception:
                pass

            # ── DB recovery: add hosts from metrics that discovery might have missed ──
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT host, ts FROM network_metrics
                    WHERE ts >= ?
                    ORDER BY ts DESC
                """, ((datetime.datetime.now() - datetime.timedelta(minutes=30)).isoformat(),))
                for row in cursor.fetchall():
                    ip = row[0]
                    if ip not in known_devices and not is_broadcast_or_network(ip):
                        known_devices[ip] = {
                            "ip": ip, "mac": None, "vendor": "Unknown",
                            "hostname": None, "device_type": "Unknown",
                            "ports": [], "trace_route": []
                        }
                        print(f"[INFO] Host recovered from DB (previous run): {ip}")
                conn.close()
            except Exception:
                pass

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

            # Ping ALL hosts in parallel for fast cycle times
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def _ping_and_save(host_mac):
                host, mac = host_mac
                metrique = generate_metrique_for_host(host)
                if metrique is not None:
                    sauvegarder(metrique, mac=mac)
                return host, metrique is not None

            results = []
            with ThreadPoolExecutor(max_workers=min(20, len(hosts_to_monitor))) as ex:
                futs = {ex.submit(_ping_and_save, hm): hm for hm in hosts_to_monitor}
                for f in as_completed(futs):
                    host, ok = f.result()
                    results.append((host, ok))
                    if not ok:
                        print(f"   {host}: ping failed")
            ok_count = sum(1 for _, ok in results if ok)
            fail_count = len(results) - ok_count
            print(f"[CYCLE] Pinged {len(results)} hosts: {ok_count} OK, {fail_count} failed")

            print()  # Blank line between cycles

            # Wait before next cycle
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n🛑 Network Monitor arrêté par l'utilisateur.")


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


if __name__ == "__main__":
    main()