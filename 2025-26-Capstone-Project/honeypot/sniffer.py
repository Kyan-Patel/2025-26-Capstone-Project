#!/usr/bin/env python3
"""
sniffer.py – Packet sniffer for the Wi-Fi honeypot
--------------------------------------------------
Listens for DNS and DHCP packets on the honeypot interface and logs them
to dns_log.csv in the format expected by portal.py:

    timestamp, vendor, mac, client_ip, info, category

Where:
  - timestamp : human-readable local time
  - vendor    : simple guess of vendor from MAC prefix (string)
  - mac       : client MAC address (source MAC)
  - client_ip : IP address on the honeypot network (e.g. 10.0.0.195)
  - info      : DNS domain OR DHCP description string
  - category  : short label, e.g. "Google", "Apple", "DNS Service", "Unknown", or "DHCP"

Run this as root:

    sudo python3 sniffer.py
"""

import csv
import os
from datetime import datetime

from scapy.all import (
    sniff,
    DNS,
    DNSQR,
    DHCP,
    BOOTP,
    Ether,
    IP,
)

# Path must match portal.py
LOG_FILE = "/home/vboxuser/honeypot/logs/dns_log.csv"

# Network interface on the honeypot that sees client traffic.
HONEYPOT_IFACE = "enp0s3"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def ensure_log_dir() -> None:
    """Make sure the directory for LOG_FILE exists."""
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def current_timestamp() -> str:
    """
    Return a human-readable local timestamp.

    If you want strict EST, you could use pytz / zoneinfo, but for the
    demo this local time string is enough.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def classify_domain(domain: str) -> str:
    """
    Very simple domain categorizer for display in the 'Category' column.

    You can tweak these rules to make the dashboard more interesting.
    """
    d = (domain or "").lower()

    # Apple background noise / services
    if "apple" in d or "icloud.com" in d or "mask-api" in d:
        return "Apple"

    # Google ecosystem
    if any(x in d for x in ["google.com", "googleapis.com", "gstatic.com", "dns.google"]):
        return "Google"

    # DNS services (Cloudflare, etc.)
    if "cloudflare-dns.com" in d:
        return "DNS Service"

    # Social / community platforms
    if any(x in d for x in [
        "facebook.com", "instagram.com", "tiktok.com",
        "twitter.com", "x.com", "snapchat.com",
        "reddit.com", "discord.com"
    ]):
        return "Social / Community"

    # Fallback
    return "Unknown"


def vendor_from_mac(mac: str) -> str:
    """
    Tiny fake 'vendor' lookup based on MAC prefix.

    For the demo, we just show the first three bytes and call it 'Device'.
    You could plug in a real OUI database here if you want.
    """
    if not mac:
        return "Unknown device"

    prefix = mac[:8].upper()
    return f"Device {prefix}"


def write_row(timestamp: str,
              vendor: str,
              mac: str,
              client_ip: str,
              info: str,
              category: str) -> None:
    """
    Append a single event row to dns_log.csv in the exact format that
    portal.py expects:

        timestamp, vendor, mac, client_ip, info, category
    """
    ensure_log_dir()
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, vendor, mac, client_ip, info, category])


# ---------------------------------------------------------------------------
# Packet handlers
# ---------------------------------------------------------------------------

def handle_dns(pkt) -> None:
    """
    Handle DNS query packets.

    We only log *queries* (qr == 0) and ignore responses. For each query,
    we extract:

      - timestamp
      - vendor + MAC (from Ethernet src)
      - client IP (from IP src)
      - queried domain name (qname)
      - category (from classify_domain)
    """
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return

    dns_layer = pkt[DNS]

    # qr == 0 means query; qr == 1 is response
    if dns_layer.qr != 0:
        return

    # Extract the queried domain name, stripping trailing dot
    qname = dns_layer[DNSQR].qname.decode(errors="ignore").rstrip(".")

    client_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""

    vendor = vendor_from_mac(src_mac)
    category = classify_domain(qname)
    ts = current_timestamp()

    # 6-column format:
    # timestamp, vendor, mac, client_ip, info, category
    write_row(ts, vendor, src_mac, client_ip, qname, category)


def handle_dhcp(pkt) -> None:
    """
    Handle DHCP packets.

    We mainly care about DHCPREQUEST or similar packets that include
    hostnames and vendor class IDs. We log:

      - timestamp
      - vendor + MAC (Ethernet src)
      - client IP (BOOTP.ciaddr)
      - info string summarizing hostname/vendor_class
      - category = 'DHCP'
    """
    if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP) and pkt.haslayer(Ether)):
        return

    bootp = pkt[BOOTP]
    src_mac = pkt[Ether].src
    vendor = vendor_from_mac(src_mac)

    # ciaddr is "client IP address" field
    client_ip = bootp.ciaddr or "0.0.0.0"

    hostname = None
    vendor_class = None

    for opt in pkt[DHCP].options:
        # DHCP options are usually ('name', value) tuples
        if isinstance(opt, tuple):
            if opt[0] == "hostname":
                hostname = opt[1].decode(errors="ignore") if isinstance(opt[1], bytes) else opt[1]
            elif opt[0] == "vendor_class_id":
                vendor_class = opt[1].decode(errors="ignore") if isinstance(opt[1], bytes) else opt[1]

    parts = []
    if hostname:
        parts.append(f"hostname={hostname}")
    if vendor_class:
        parts.append(f"vendor={vendor_class}")

    details = ", ".join(parts) if parts else "no extra details"
    info = f"DHCP Request: {details}"

    ts = current_timestamp()
    write_row(ts, vendor, src_mac, client_ip, info, "DHCP")


def packet_callback(pkt) -> None:
    """
    Callback for each captured packet.

    We route packets to either the DHCP handler or the DNS handler.
    """
    # DHCP packets: UDP ports 67/68 with DHCP + BOOTP
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        handle_dhcp(pkt)
    # DNS packets: UDP port 53 with DNS + DNSQR
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        handle_dns(pkt)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Start sniffing on the honeypot interface."""
    ensure_log_dir()
    print(f"[*] Sniffer running on interface {HONEYPOT_IFACE}")
    print(f"[*] Logging to {LOG_FILE}")
    print("[*] Capturing DNS (udp port 53) and DHCP (udp port 67 or 68) traffic...")

    # BPF filter: DNS queries (53) + DHCP (67/68)
    bpf_filter = "udp port 53 or (udp and (port 67 or port 68))"

    sniff(
        iface=HONEYPOT_IFACE,
        filter=bpf_filter,
        prn=packet_callback,
        store=False,
    )


if __name__ == "__main__":
    main()
