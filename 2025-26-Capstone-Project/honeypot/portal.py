#!/usr/bin/env python3
"""
portal.py – Flask dashboard for the Wi-Fi honeypot
--------------------------------------------------
Reads dns_log.csv (written by sniffer.py) and displays a live,
auto-refreshing table of recent activity.

Supports TWO possible CSV layouts:

5-column format:
    timestamp, device_label, client_ip, info, category

6-column format:
    timestamp, vendor, mac, client_ip, info, category

We reconstruct "Vendor (MAC)" for display automatically.

The UI includes:
  - Icons for DNS 🌐 and DHCP 📡
  - Category pills with colored dots
  - Hover effects and improved styling
  - Type-based left border color
"""

from flask import Flask, render_template_string
import csv
import os

app = Flask(__name__)

# Path to the log file produced by sniffer.py
LOG_FILE = "/home/vboxuser/honeypot/logs/dns_log.csv"

# Substrings for filtering boring DNS traffic
IGNORE_SUBSTRINGS = [
    "apple.com",
    "icloud.com",
    "gstatic.com",
    "googleapis.com",
    "time-ios",
    "verizon.telephony",
    "rcs.telephony",
    ".arpa",
    "msftncsi.com",
    "windows.com",
    "ubuntu.com",
    "ntp.org",
]

# ------------------------ NEW UI TEMPLATE -------------------------

HTML = """
<!doctype html>
<html>
<head>
    <title>Wi-Fi Honeypot Activity</title>
    <meta http-equiv="refresh" content="5">

    <style>
        html, body {
            margin: 0;
            padding: 0;
        }

        body  {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: radial-gradient(circle at top left, #1d2240, #020617 55%);
            color: #e5e7eb;
            padding: 24px;
        }

        h1 {
            color: #fbbf24;
            margin-bottom: 0.25rem;
            letter-spacing: 0.05em;
        }

        p {
            color: #cbd5f5;
            max-width: 900px;
            line-height: 1.5;
        }

        .hint {
            font-size: 0.8rem;
            color: #9ca3af;
            margin-top: 8px;
        }

        /* ----- TABLE ----- */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(15, 23, 42, 0.9);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 18px 45px rgba(0, 0, 0, 0.55);
        }

        thead {
            background: linear-gradient(to right, #020617, #0b1120);
        }

        th, td {
            padding: 10px 12px;
            border-bottom: 1px solid #1e293b;
            font-size: 0.9rem;
        }

        th {
            text-align: left;
            color: #9ca3af;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-size: 0.75rem;
        }

        tbody tr:nth-child(even) {
            background: rgba(15, 23, 42, 0.85);
        }
        tbody tr:nth-child(odd) {
            background: rgba(12, 20, 38, 0.9);
        }
        tbody tr:hover {
            background: #111827;
            transition: background 120ms ease-out;
        }

        /* Type-based row highlights */
        .event-dns  td {
            border-left: 3px solid rgba(56, 189, 248, 0.5);
        }
        .event-dhcp td {
            border-left: 3px solid rgba(250, 204, 21, 0.8);
        }

        /* Device label pill */
        .tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 999px;
            background: rgba(30, 64, 175, 0.2);
            border: 1px solid rgba(129, 140, 248, 0.5);
            font-size: 0.75rem;
            color: #c7d2fe;
            margin-bottom: 2px;
        }

        .mac {
            font-size: 0.8rem;
            color: #9ca3af;
        }

        /* TYPE CHIPS */
        .type-chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.78rem;
            padding: 3px 9px;
            border-radius: 999px;
            font-weight: 500;
        }
        .type-icon { font-size: 0.9rem; }

        .chip-dns {
            background: rgba(56, 189, 248, 0.15);
            color: #e0f2fe;
            border: 1px solid rgba(56, 189, 248, 0.7);
        }
        .chip-dhcp {
            background: rgba(250, 204, 21, 0.16);
            color: #fef9c3;
            border: 1px solid rgba(250, 204, 21, 0.8);
        }

        /* CATEGORY PILL */
        .category-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 2px 10px;
            border-radius: 999px;
            font-size: 0.78rem;
            background: rgba(148, 163, 184, 0.15);
            color: #e5e7eb;
        }
        .category-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
        }

        .category-apple      .category-dot { background: #f97316; }
        .category-google     .category-dot { background: #22c55e; }
        .category-dns-service .category-dot { background: #38bdf8; }
        .category-dhcp       .category-dot { background: #eab308; }
        .category-unknown    .category-dot { background: #a855f7; }

        /* Info column font */
        .info-cell {
            font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
            font-size: 0.82rem;
        }

        .timestamp-cell {
            font-size: 0.82rem;
            white-space: nowrap;
        }
    </style>
</head>

<body>

<h1>Wi-Fi Honeypot Activity</h1>
<p>
  This dashboard shows a live view of traffic from devices connected to the fake Wi-Fi.
  We log both <strong>DNS</strong> requests (services a device is trying to reach)
  and <strong>DHCP</strong> events (identity information like hostname/vendor class).
</p>
<p class="hint">Page auto-refreshes every 5 seconds.</p>

<table>
  <thead>
    <tr>
      <th>Timestamp</th>
      <th>Type</th>
      <th>Device (Vendor + MAC)</th>
      <th>Client IP</th>
      <th>Info</th>
      <th>Category</th>
    </tr>
  </thead>

  <tbody>
  {% for row in rows %}
  {% set cat_class = row.category.lower().replace(' ', '-').replace('/', '-').replace('.', '-') %}
  <tr class="{{ row.type_class }} category-{{ cat_class }}">
    <td class="timestamp-cell">{{ row.timestamp }}</td>

    <td>
      <span class="type-chip {{ row.type_chip }}">
        <span class="type-icon">
          {% if row.event_type == "DNS" %}🌐{% else %}📡{% endif %}
        </span>
        {{ row.event_type }}
      </span>
    </td>

    <td>
      <span class="tag">{{ row.vendor }}</span><br>
      <span class="mac">{{ row.mac }}</span>
    </td>

    <td>{{ row.ip }}</td>

    <td class="info-cell">{{ row.info }}</td>

    <td>
      <span class="category-pill">
        <span class="category-dot"></span>
        {{ row.category }}
      </span>
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>

{% if not rows %}
<p class="hint">No events yet. Connect a device and browse a few sites.</p>
{% endif %}

</body>
</html>
"""

# ---------------------------- PARSER LOGIC -----------------------------

def is_boring_dns(info: str) -> bool:
    if not info:
        return True
    d = info.lower()
    return any(substr in d for substr in IGNORE_SUBSTRINGS)


def parse_log_file():
    rows = []

    if not os.path.exists(LOG_FILE):
        return rows

    with open(LOG_FILE, newline="") as f:
        reader = csv.reader(f)

        for raw in reader:
            if len(raw) < 5:
                continue

            if raw[0].lower().startswith("timestamp"):
                continue

            # 6-column format
            if len(raw) >= 6:
                timestamp, vendor_col, mac_col, ip, info, category = raw[:6]
                device_label = f"{vendor_col} ({mac_col})"

            # 5-column legacy format
            else:
                timestamp, device_label, ip, info, category = raw[:5]

            # Determine event type
            info_str = info or ""
            category_str = category or ""

            if info_str.startswith("DHCP") or category_str.upper() == "DHCP":
                event_type = "DHCP"
                type_class = "event-dhcp"
                type_chip = "chip-dhcp"
            else:
                event_type = "DNS"
                type_class = "event-dns"
                type_chip = "chip-dns"
                if is_boring_dns(info_str):
                    continue

            # Split Vendor (MAC)
            vendor = device_label
            mac = ""
            if "(" in device_label and device_label.endswith(")"):
                try:
                    vendor_part, mac_part = device_label.split("(", 1)
                    vendor = vendor_part.strip()
                    mac = mac_part.rstrip(")").strip()
                except:
                    pass

            rows.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "type_class": type_class,
                "type_chip": type_chip,
                "vendor": vendor,
                "mac": mac,
                "ip": ip,
                "info": info_str,
                "category": category_str,
            })

    return rows[-40:]


@app.route("/")
def index():
    rows = parse_log_file()
    return render_template_string(HTML, rows=rows)


if __name__ == "__main__":
    print("[*] Captive portal running at http://0.0.0.0:80/")
    app.run(host="0.0.0.0", port=80)
