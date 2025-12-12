# Wi-Fi Honeypot Capstone Project (2025–2026)

This repository contains the complete implementation of our cybersecurity capstone project:  
a functional **Wi-Fi Honeypot** designed to demonstrate how attackers deploy rogue access points to capture sensitive metadata from unsuspecting users.

The honeypot simulates a malicious open Wi-Fi network that appears legitimate to end-users while silently logging DNS and DHCP activity.  
It is intended for **educational use only** and was built as part of the 2025–2026 Capstone Project at American University.

---

## Overview

Modern devices leak significant metadata even before encrypted communication begins.  
This honeypot highlights:

- How attackers create fraudulent Wi-Fi networks
- What information can be captured without breaking encryption
- How DNS/DHCP traffic exposes device identity, behavior, and browsing patterns
- The risks users face when connecting to open networks

Our implementation includes:

- A virtualized rogue Wi-Fi access point  
- Real-time DNS and DHCP packet capture  
- A Flask dashboard that displays activity in a clean, filterable UI  
- NAT forwarding so the network appears to provide working internet  
- Automated scripts for repeatable deployment  

---

## 🏗 Project Components

### **1. Rogue Access Point**
Built using:

- **Ubuntu VM (VirtualBox)**
- **Atheros AR9271 USB Adapter** (AP-mode capable)
- **hostapd** for broadcasting the SSID
- **dnsmasq** for DHCP and DNS resolution

### **2. NAT & Routing**
`iptables` is used to forward client traffic through the VM’s real network connection, making the fake Wi-Fi appear legitimate.

### **3. Packet Sniffer**
A custom Python script (`sniffer.py`) using **Scapy** captures:

- DNS Requests  
- DHCP Discovery / Request / ACK events  
- MAC address & vendor identification  
- Domain categorization (Search, Social, Ads, Other)  
- Timestamps (EST)

Captured data is stored in CSV format.

### **4. Real-Time Dashboard**
A Flask app (`portal.py`) serves a live dashboard at:

Features:

- Auto-refresh every 5 seconds  
- Event type labeling (DNS vs DHCP)  
- Vendor and MAC extraction  
- Domain filtering to remove OS noise  
- Clean, color-coded table interface  

---

## 📁 Repository Structure
2025-26-Capstone-Project/
│
├── honeypot/
│ ├── start_ap.sh # Script to start AP, assign IP, launch hostapd/dnsmasq
│ ├── sniffer.py # Scapy sniffer for DNS & DHCP packets
│ ├── portal.py # Flask dashboard for live monitoring
│ │
│ ├── config/
│ │ ├── hostapd.conf # AP configuration (SSID, channel, interface)
│ │ └── dnsmasq.conf # DHCP/DNS configuration
│ │
│ ├── logs/
│ │ └── .gitignore # Prevents uploading captured user traffic
│ │
│ └── README.md # Honeypot technical documentation
│
└── README.md # (This file) Project Overview
