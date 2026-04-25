"""
Ethical Packet Sniffer Lab Tool

Purpose:
- Capture only authorized/lab traffic.
- Prefer loopback or a clearly allowed lab interface.
- Support safe PCAP-file analysis if live capture permissions are difficult.
- Decode basic Ethernet/raw, IP, TCP/UDP, DNS, and HTTP request-line data.
- Redact sensitive information before writing output.

Important:
Do not use this tool to capture other people's traffic.
Do not use this tool to bypass operating system permissions.
Do not add stealth, persistence, hiding, or evasion features.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional


try:
    from scapy.all import (
        sniff,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        DNSQR,
        Raw,
        conf,
        get_if_list,
    )
except ImportError:
    print("ERROR: Scapy is not installed. Run: py -m pip install scapy")
    sys.exit(1)


# -----------------------------
# Safe defaults and allowlists
# -----------------------------

DEFAULT_BPF_FILTER = "tcp port 80 or udp port 53"

# For live capture, the interface must look like loopback or lab traffic
# unless the user explicitly allowlists another lab interface.
DEFAULT_ALLOWED_IFACE_KEYWORDS = [
    "loopback",
    "npf_loopback",
    "localhost",
    "lo",
    "lab",
]

# For PCAP mode, only allow .pcap or .pcapng files.
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng"}


# -----------------------------
# Redaction patterns
# -----------------------------

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

AUTH_HEADER_RE = re.compile(
    r"(?im)^(authorization\s*:\s*)(.+)$"
)

COOKIE_HEADER_RE = re.compile(
    r"(?im)^((?:cookie|set-cookie)\s*:\s*)(.+)$"
)

SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:password|pass|pwd|token|api_key|apikey|secret|session|auth|key)=)([^&#\s]*)"
)

HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
}


# -----------------------------
# Redaction helpers
# -----------------------------

def mask_ipv4(ip_address: str) -> str:
    """
    Partially masks an IPv4 address.

    Example:
    192.168.1.25 becomes 192.168.1.xxx
    """
    parts = ip_address.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return ip_address


def redact_sensitive(text: str) -> str:
    """
    Redacts sensitive information from a string before output is saved.
    """
    if not isinstance(text, str):
        return text

    # Redact Authorization header values
    text = AUTH_HEADER_RE.sub(r"\1[REDACTED_AUTHORIZATION]", text)

    # Redact Cookie and Set-Cookie header values
    text = COOKIE_HEADER_RE.sub(r"\1[REDACTED_COOKIE]", text)

    # Redact emails
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)

    # Redact sensitive query string values
    text = SECRET_QUERY_RE.sub(r"\1[REDACTED_SECRET]", text)

    # Partially mask IPv4 addresses
    text = IPV4_RE.sub(lambda match: mask_ipv4(match.group(0)), text)

    return text


def sanitize_value(value: Any) -> Any:
    """
    Recursively redacts strings inside dictionaries and lists.
    """
    if isinstance(value, dict):
        return {key: sanitize_value(val) for key, val in value.items()}

    if isinstance(value, list):
        return [sanitize_value(item) for item in value]

    if isinstance(value, str):
        return redact_sensitive(value)

    return value


# -----------------------------
# HTTP parsing
# -----------------------------

def parse_http_from_payload(payload: bytes) -> Optional[Dict[str, str]]:
    """
    Attempts to parse an unencrypted HTTP request from raw TCP payload bytes.

    This only works for plaintext HTTP, not HTTPS.
    """
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split(" ")

    if len(parts) < 3:
        return None

    method, path, version = parts[0], parts[1], parts[2]

    if method not in HTTP_METHODS:
        return None

    headers: Dict[str, str] = {}

    for line in lines[1:]:
        if line.strip() == "":
            break

        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.lower().strip()] = value.strip()

    return {
        "method": method,
        "path": path,
        "version": version,
        "host": headers.get("host", ""),
        "request_line": request_line,
    }


# -----------------------------
# Packet decoding
# -----------------------------

def decode_packet(packet: Any, packet_number: int) -> Dict[str, Any]:
    """
    Converts one Scapy packet into a safe dictionary summary.
    """
    result: Dict[str, Any] = {
        "packet_number": packet_number,
        "packet_length_bytes": len(packet),
        "layers": [],
    }

    # Ethernet or raw/loopback
    if packet.haslayer(Ether):
        result["layers"].append("Ethernet")
        result["link_layer"] = {
            "type": "Ethernet",
            "note": "Ethernet layer present",
        }
    else:
        result["layers"].append("Raw/Loopback")
        result["link_layer"] = {
            "type": "Raw or Loopback",
            "note": "No Ethernet layer detected; common for loopback captures",
        }

    # IPv4
    if packet.haslayer(IP):
        ip = packet[IP]
        result["layers"].append("IPv4")
        result["ip"] = {
            "version": 4,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol_number": ip.proto,
            "ttl": ip.ttl,
        }

    # IPv6, included just in case your laptop produces IPv6 traffic
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        result["layers"].append("IPv6")
        result["ip"] = {
            "version": 6,
            "src_ip": ipv6.src,
            "dst_ip": ipv6.dst,
            "next_header": ipv6.nh,
            "hop_limit": ipv6.hlim,
        }

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["layers"].append("TCP")
        result["transport"] = {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": str(tcp.flags),
        }

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["layers"].append("UDP")
        result["transport"] = {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
        }

    # DNS query
    if packet.haslayer(DNSQR):
        dns_query = packet[DNSQR]
        qname = dns_query.qname

        if isinstance(qname, bytes):
            qname = qname.decode(errors="ignore")

        result["layers"].append("DNS")
        result["dns"] = {
            "query_name": str(qname).rstrip("."),
            "query_type": dns_query.qtype,
        }

    # HTTP request line, if plaintext HTTP exists
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        raw_bytes = bytes(packet[Raw].load)
        http_info = parse_http_from_payload(raw_bytes)

        if http_info:
            result["layers"].append("HTTP")
            result["http"] = http_info

    # Redact before returning the packet summary
    return sanitize_value(result)


# -----------------------------
# Safety checks
# -----------------------------

def interface_is_allowed(interface_name: str, extra_allowed: list[str]) -> bool:
    """
    Checks whether the requested live-capture interface is allowed.
    """
    lowered = interface_name.lower()

    allowed_keywords = DEFAULT_ALLOWED_IFACE_KEYWORDS + [
        item.lower() for item in extra_allowed
    ]

    return any(keyword in lowered for keyword in allowed_keywords)


def validate_pcap_path(pcap_path: str) -> Path:
    """
    Checks that a PCAP path exists and has an allowed extension.
    """
    path = Path(pcap_path)

    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if path.suffix.lower() not in ALLOWED_PCAP_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng files are allowed.")

    return path


# -----------------------------
# Output writer
# -----------------------------

class JsonlWriter:
    """
    Writes one JSON object per line.
    """

    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.output_path.open("w", encoding="utf-8")

    def write(self, data: Dict[str, Any]) -> None:
        self.file.write(json.dumps(data, indent=None) + "\n")
        self.file.flush()

    def close(self) -> None:
        self.file.close()


# -----------------------------
# Interface listing
# -----------------------------

def list_interfaces() -> None:
    """
    Prints Scapy-visible interfaces.
    """
    print("\nScapy-visible interfaces:\n")

    try:
        for index, iface in enumerate(get_if_list(), start=1):
            print(f"{index}. {iface}")
    except Exception as error:
        print(f"Could not list interfaces using get_if_list(): {error}")

    print("\nDetailed interface view, if available:\n")

    try:
        conf.ifaces.show()
    except Exception as error:
        print(f"Could not show detailed interfaces: {error}")

# -----------------------------
# Python-level packet filtering for PCAP mode
# -----------------------------

def packet_matches_lab_filter(packet: Any, filter_text: str) -> bool:
    """
    Beginner-friendly replacement for BPF filtering in PCAP mode.

    Why this exists:
    - On Windows, Scapy may try to use tcpdump when applying a BPF filter
      to an offline PCAP file.
    - If tcpdump is not installed, PCAP mode can crash.
    - This function safely handles the lab filters we need for this project.

    Supported examples:
    - tcp port 80 or udp port 53
    - udp port 53
    - tcp port 80
    - tcp port 8000
    - port 80
    - port 53
    - tcp
    - udp

    If the filter is empty, it accepts all packets.
    """

    if not filter_text:
        return True

    filter_text = filter_text.lower().strip()

    # No filter means accept everything
    if filter_text in ["", "none", "all"]:
        return True

    # Match: tcp
    if filter_text == "tcp":
        return packet.haslayer(TCP)

    # Match: udp
    if filter_text == "udp":
        return packet.haslayer(UDP)

    # Match: udp port 53
    if filter_text == "udp port 53":
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return udp.sport == 53 or udp.dport == 53
        return False

    # Match: tcp port 80
    if filter_text == "tcp port 80":
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return tcp.sport == 80 or tcp.dport == 80
        return False

    # Match: tcp port 8000
    if filter_text == "tcp port 8000":
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return tcp.sport == 8000 or tcp.dport == 8000
        return False

    # Match: port 80
    if filter_text == "port 80":
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return tcp.sport == 80 or tcp.dport == 80
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return udp.sport == 80 or udp.dport == 80
        return False

    # Match: port 53
    if filter_text == "port 53":
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return tcp.sport == 53 or tcp.dport == 53
        if packet.haslayer(UDP):
            udp = packet[UDP]
            return udp.sport == 53 or udp.dport == 53
        return False

    # Match: tcp port 80 or udp port 53
    if filter_text == "tcp port 80 or udp port 53":
        tcp_80 = False
        udp_53 = False

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            tcp_80 = tcp.sport == 80 or tcp.dport == 80

        if packet.haslayer(UDP):
            udp = packet[UDP]
            udp_53 = udp.sport == 53 or udp.dport == 53

        return tcp_80 or udp_53

    # If an unsupported filter is typed, fail safely by accepting nothing.
    print(f"Unsupported PCAP filter: {filter_text}")
    print("Supported PCAP filters include:")
    print("- tcp port 80 or udp port 53")
    print("- udp port 53")
    print("- tcp port 80")
    print("- tcp port 8000")
    print("- port 80")
    print("- port 53")
    print("- tcp")
    print("- udp")

    return False
# -----------------------------
# Capture modes
# -----------------------------

def run_pcap_mode(args: argparse.Namespace) -> None:
    """
    Reads packets from a PCAP file.
    """
    pcap_path = validate_pcap_path(args.pcap)

    writer = JsonlWriter(args.out)
    packet_counter = {"count": 0}

    def handle_packet(packet: Any) -> None:
        packet_counter["count"] += 1
        decoded = decode_packet(packet, packet_counter["count"])
        writer.write(decoded)
        print(json.dumps(decoded, indent=2))

    print(f"\nReading PCAP file: {pcap_path}")
    print(f"BPF filter: {args.filter}")
    print(f"Packet count limit: {args.count}")
    print(f"Output file: {args.out}\n")

    try:
        sniff(
            offline=str(pcap_path),
            lfilter=lambda packet: packet_matches_lab_filter(packet, args.filter),
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    finally:
        writer.close()
        
    print(f"\nDone. Wrote redacted output to: {args.out}")


def run_live_mode(args: argparse.Namespace) -> None:
    """
    Captures live traffic from an allowed loopback/lab interface.
    """
    if not args.iface:
        print("ERROR: Live mode requires --iface.")
        print("For safety, this tool does not sniff all interfaces.")
        sys.exit(1)

    if not interface_is_allowed(args.iface, args.allow_iface):
        print("ERROR: Interface is not allowlisted.")
        print("Use loopback when possible, or explicitly allow a lab interface.")
        print("Example:")
        print('py sniffer.py --mode live --iface "NPF_Loopback" --allow-iface "NPF_Loopback"')
        sys.exit(1)

    writer = JsonlWriter(args.out)
    packet_counter = {"count": 0}

    def handle_packet(packet: Any) -> None:
        packet_counter["count"] += 1
        decoded = decode_packet(packet, packet_counter["count"])
        writer.write(decoded)
        print(json.dumps(decoded, indent=2))

    print(f"\nStarting live capture on interface: {args.iface}")
    print(f"BPF filter: {args.filter}")
    print(f"Packet count limit: {args.count}")
    print(f"Output file: {args.out}")
    print("\nOnly capture traffic you are authorized to inspect.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\nPermission error.")
        print("Live capture may require running PowerShell/Command Prompt as Administrator.")
        print("Safe fallback: use PCAP mode instead.")
    except Exception as error:
        print(f"\nLive capture failed: {error}")
        print("Safe fallback: use PCAP mode instead.")
    finally:
        writer.close()

    print(f"\nDone. Wrote redacted output to: {args.out}")


# -----------------------------
# CLI
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ethical packet sniffer for authorized lab traffic only."
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List network interfaces visible to Scapy and exit.",
    )

    parser.add_argument(
        "--mode",
        choices=["pcap", "live"],
        default="pcap",
        help="Capture mode. Default is pcap for safety.",
    )

    parser.add_argument(
        "--pcap",
        help="Path to .pcap or .pcapng file for pcap mode.",
    )

    parser.add_argument(
        "--iface",
        help="Network interface for live mode. Use loopback/lab interface only.",
    )

    parser.add_argument(
        "--allow-iface",
        action="append",
        default=[],
        help="Extra allowed interface keyword for a known lab interface.",
    )

    parser.add_argument(
        "--filter",
        default=DEFAULT_BPF_FILTER,
        help='BPF filter, for example: "tcp port 80 or udp port 53".',
    )

    parser.add_argument(
        "--count",
        type=int,
        default=25,
        help="Number of packets to capture/read. Default is 25.",
    )

    parser.add_argument(
        "--out",
        default="output/packets.jsonl",
        help="Output JSONL file path.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    if args.mode == "pcap":
        if not args.pcap:
            print("ERROR: PCAP mode requires --pcap.")
            print("Example:")
            print("py sniffer.py --mode pcap --pcap samples/lab_test.pcap")
            sys.exit(1)

        run_pcap_mode(args)

    elif args.mode == "live":
        run_live_mode(args)


if __name__ == "__main__":
    main()
