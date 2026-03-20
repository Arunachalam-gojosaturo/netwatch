<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000d1a,50:003322,100:000d1a&height=200&section=header&text=NETWATCH&fontSize=75&fontColor=00ff88&fontAlignY=52&animation=fadeIn&desc=v1.0%20%7C%20Real-Time%20Network%20Intrusion%20Monitor&descSize=15&descAlignY=73&descColor=4a9ebe"/>

</div>

<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=14&pause=900&color=00FF88&center=true&vCenter=true&width=780&lines=NETWATCH+INITIALIZING...;Loading+threat+intel+feeds...+%E2%9C%93;Connection+monitor+active...+%E2%9C%93;Port+scan+detector+armed...+%E2%9C%93;HTML+report+engine+ready...+%E2%9C%93;%5B+ALL+MODULES+ONLINE+%5D+Your+network+is+being+watched." alt="Typing SVG"/>

</div>

<br/>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-00ff88?style=flat-square&logo=python&logoColor=black&labelColor=000d1a)
![Scapy](https://img.shields.io/badge/Packet-Scapy-00ff88?style=flat-square&labelColor=000d1a)
![psutil](https://img.shields.io/badge/System-psutil-00ff88?style=flat-square&labelColor=000d1a)
![Alerts](https://img.shields.io/badge/Alerts-Telegram%20%7C%20Ntfy-00ff88?style=flat-square&labelColor=000d1a)
![License](https://img.shields.io/badge/License-MIT%202026-00ff88?style=flat-square&labelColor=000d1a)
![Use](https://img.shields.io/badge/Use-Defensive%20%7C%20Your%20Own%20System-22c55e?style=flat-square&labelColor=000d1a)

</div>

---

## `>> WHAT IS NETWATCH?`

```
A Python-based defensive security tool that watches YOUR OWN system
in real time for suspicious network activity.

It detects port scans hitting your machine, flags connections to known
malicious IPs, audits open ports, and fires instant alerts to your
Telegram or Ntfy — all from a clean interactive terminal menu.
```

> ⚠️ **Defensive tool only.** Monitor systems you own or have permission to monitor.

---

## `>> QUICK START`

```bash
# Clone
git clone https://github.com/Arunachalam-gojosaturo/netwatch.git
cd netwatch

# Install deps
python3 netwatch.py --install

# Run (root needed for packet sniffing)
sudo python3 netwatch.py

# Quick port audit only
sudo python3 netwatch.py --audit

# Generate HTML report
sudo python3 netwatch.py --report
```

---

## `>> MODULES`

<div align="center">
<table>
<tr>
<td width="50%" valign="top">

### 🔍 Live Monitor
```yaml
watches      : active TCP/UDP connections
detects      : new connections every 3s
flags        : known malicious IPs
alerts on    : suspicious port inbound
threat_feed  : ipsum blocklist (public)
alerts       : Telegram + Ntfy (instant)
```

</td>
<td width="50%" valign="top">

### 🚨 Port Scan Detector
```yaml
engine       : Scapy packet sniffer
method       : SYN packet counting
threshold    : 20 probes / 10 seconds
also detects : ICMP flood (>50 pings/10s)
response     : CRITICAL alert + log
reset        : auto after detection
```

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔓 Port Audit
```yaml
lists        : all LISTEN + ESTABLISHED
flags        : 15 suspicious port types
shows        : PID + process name
output       : color-coded terminal table
extra        : HTML report generation
```

</td>
<td width="50%" valign="top">

### 📊 Interface Stats
```yaml
shows        : all network interfaces
displays     : IP, status, speed
traffic      : bytes sent / received
live conns   : via ss -tunp
format       : per-interface breakdown
```

</td>
</tr>
</table>
</div>

---

## `>> SUSPICIOUS PORTS WATCHED`

```
22   SSH          3389  RDP          445   SMB
23   Telnet       1433  MSSQL        3306  MySQL
5432 PostgreSQL   6379  Redis        27017 MongoDB
9200 Elasticsearch  2375 Docker(unauth)  4444 Metasploit
5555 Android ADB   8080 Alt-HTTP
```

---

## `>> MAIN MENU`

```
  ─── MONITORS ───────────────────────────────
  [1]  Live Monitor      — connections + scan detection
  [2]  Port Audit        — open ports on this system
  [3]  Interface Stats   — traffic per interface
  [4]  Live Connections  — active TCP/UDP (ss)

  ─── INTELLIGENCE ───────────────────────────
  [5]  Update Threat Intel — refresh malicious IP list

  ─── OUTPUT ─────────────────────────────────
  [6]  Generate HTML Report
  [7]  View Log

  ─── SETUP ──────────────────────────────────
  [8]  Configure Alerts (Telegram / Ntfy)
  [9]  Install Dependencies

  [Q]  Quit
```

---

## `>> ALERT SETUP`

```bash
# Run configure from menu [8] or edit:
~/.netwatch/config.json

{
  "telegram_token"  : "your_bot_token",
  "telegram_chat_id": "your_chat_id",
  "ntfy_topic"      : "netwatch-alerts",
  "whitelist_ips"   : ["127.0.0.1"],
  "alert_threshold" : 20,
  "scan_window_sec" : 10,
  "alert_telegram"  : true,
  "alert_ntfy"      : true,
  "log_all"         : false
}
```

---

## `>> FILE STRUCTURE`

```
netwatch/
├── netwatch.py          ← Main script (everything in one file)
└── ~/.netwatch/
    ├── config.json      ← Your config + alert settings
    ├── netwatch.log     ← All events logged here
    ├── report.html      ← Generated HTML report
    └── threat_ips.json  ← Cached malicious IP list
```

---

## `>> REQUIREMENTS`

```
Python 3.8+
psutil      — connection + process monitoring
scapy       — packet capture (port scan detection)
requests    — threat intel feeds + alerts

# Auto-installed via option [9] or:
pip install psutil scapy requests
```

---

## `>> CREATOR`

<div align="center">

```
  BUILT BY  : ARUNACHALAM
  ALIAS     : gojosaturo
  BASE      : Vellore, Tamil Nadu 🇮🇳
  OS        : Arch Linux + Hyprland
  MOTIVE    : Know what's happening on your own network.
```

[![GitHub](https://img.shields.io/badge/GITHUB-Arunachalam--gojosaturo-00ff88?style=for-the-badge&logo=github&logoColor=black&labelColor=000d1a)](https://github.com/Arunachalam-gojosaturo)
[![Instagram](https://img.shields.io/badge/INSTAGRAM-@saturogojo__ac-00ff88?style=for-the-badge&logo=instagram&logoColor=black&labelColor=000d1a)](https://instagram.com/saturogojo_ac)

</div>

---

<div align="center">

*Watch your network. Trust nothing. Verify everything.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000d1a,50:003322,100:000d1a&height=100&section=footer&text=NETWATCH+v1.0+%7C+BUILT+BY+ARUNACHALAM&fontSize=14&fontColor=00ff88&animation=fadeIn"/>

</div>
