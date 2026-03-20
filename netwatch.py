#!/usr/bin/env python3
# ============================================================
#   NETWATCH v1.0 — Real-Time Network Intrusion Monitor
#   Built by: ARUNACHALAM (gojosaturo)
#   GitHub  : https://github.com/Arunachalam-gojosaturo
#   Purpose : Monitor YOUR OWN system for suspicious traffic
#   License : MIT 2026
# ============================================================

import os, sys, time, json, socket, logging, argparse
import datetime, threading, subprocess
from pathlib import Path
from collections import defaultdict

# ─── OPTIONAL IMPORTS ─────────────────────────────────────
try:    import psutil;                          PSUTIL_OK = True
except: PSUTIL_OK = False
try:    import requests;                        REQUESTS_OK = True
except: REQUESTS_OK = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except: SCAPY_OK = False

# ─── COLORS ───────────────────────────────────────────────
RED    = "\033[0;31m";  GREEN  = "\033[0;32m"; YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m";  WHITE  = "\033[1;37m"; DIM    = "\033[2m"
BOLD   = "\033[1m";     RESET  = "\033[0m"

# ─── PATHS ────────────────────────────────────────────────
BASE_DIR    = Path.home() / ".netwatch"
CONFIG_FILE = BASE_DIR / "config.json"
LOG_FILE    = BASE_DIR / "netwatch.log"
REPORT_FILE = BASE_DIR / "report.html"
THREAT_FILE = BASE_DIR / "threat_ips.json"

DEFAULT_CONFIG = {
    "telegram_token"  : "",
    "telegram_chat_id": "",
    "ntfy_topic"      : "",
    "whitelist_ips"   : ["127.0.0.1", "::1"],
    "alert_threshold" : 20,
    "scan_window_sec" : 10,
    "alert_telegram"  : False,
    "alert_ntfy"      : False,
    "log_all"         : False
}

# ─── SUSPICIOUS PORTS ─────────────────────────────────────
SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
    139: "NetBIOS", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 2375: "Docker(unauth)",
    4444: "Metasploit", 5555: "ADB", 8080: "Alt-HTTP"
}

# ─── THREAT FEEDS ─────────────────────────────────────────
THREAT_FEEDS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]

# ============================================================
# BANNER
# ============================================================
def banner():
    os.system("clear")
    print(f"""{CYAN}
  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
{RESET}{DIM}  v1.0 | Real-Time Network Intrusion Monitor | by Arunachalam (gojosaturo){RESET}
{DIM}  ─────────────────────────────────────────────────────────────────────{RESET}
""")

# ============================================================
# SETUP
# ============================================================
def setup_dirs():
    BASE_DIR.mkdir(exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print(f"{GREEN}[✓]{RESET} Config created: {CYAN}{CONFIG_FILE}{RESET}")

def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)

def setup_logging():
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

# ============================================================
# DEPENDENCY INSTALLER
# ============================================================
def install_deps():
    print(f"\n{CYAN}[*]{RESET} Checking dependencies...\n")
    for module, pkg in [("psutil","psutil"),("scapy","scapy"),("requests","requests")]:
        try:
            __import__(module)
            print(f"  {GREEN}✓{RESET} {module}")
        except ImportError:
            print(f"  {YELLOW}!{RESET} Installing {pkg}...")
            os.system(f"{sys.executable} -m pip install {pkg} -q")
            print(f"  {GREEN}✓{RESET} {module} installed")
    print(f"\n{GREEN}[✓]{RESET} All dependencies ready.\n")

# ============================================================
# THREAT INTEL
# ============================================================
def load_threat_intel():
    threat_ips = set()
    if THREAT_FILE.exists():
        with open(THREAT_FILE) as f:
            data = json.load(f)
        threat_ips = set(data.get("ips", []))
        print(f"{GREEN}[✓]{RESET} Loaded {len(threat_ips)} threat IPs from cache.")
        return threat_ips
    if not REQUESTS_OK:
        return threat_ips
    print(f"{CYAN}[*]{RESET} Fetching threat intel feeds...")
    for url in THREAT_FEEDS:
        try:
            r = requests.get(url, timeout=10)
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ip = line.split()[0]
                    try:
                        socket.inet_aton(ip)
                        threat_ips.add(ip)
                    except Exception:
                        pass
        except Exception:
            pass
    with open(THREAT_FILE, "w") as f:
        json.dump({"ips": list(threat_ips), "updated": str(datetime.datetime.now())}, f)
    print(f"{GREEN}[✓]{RESET} {len(threat_ips)} threat IPs loaded.")
    return threat_ips

# ============================================================
# ALERT ENGINE
# ============================================================
def fire_alert(config, level, message):
    ts     = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": CYAN, "WARN": YELLOW, "CRITICAL": RED}
    c      = colors.get(level, WHITE)
    print(f"  {c}[{level}]{RESET} {DIM}{ts}{RESET}  {message}")
    logging.info(f"[{level}] {message}")
    if level == "CRITICAL":
        msg = f"NETWATCH [{level}] {ts}\n{message}"
        if config.get("alert_telegram") and REQUESTS_OK:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{config['telegram_token']}/sendMessage",
                    data={"chat_id": config["telegram_chat_id"], "text": msg}, timeout=5)
            except Exception:
                pass
        if config.get("alert_ntfy") and REQUESTS_OK:
            try:
                requests.post(f"https://ntfy.sh/{config['ntfy_topic']}",
                    data=msg.encode(), headers={"Title":"NetWatch Alert","Priority":"high"}, timeout=5)
            except Exception:
                pass

# ============================================================
# MODULE 1 — CONNECTION MONITOR
# ============================================================
class ConnectionMonitor:
    def __init__(self, config, threat_ips):
        self.config     = config
        self.threat_ips = threat_ips
        self.seen       = set()
        self.running    = False
        self.whitelist  = set(config.get("whitelist_ips", []))

    def start(self):
        self.running = True
        print(f"{GREEN}[✓]{RESET} Connection monitor active.\n")
        while self.running:
            self._check()
            time.sleep(3)

    def stop(self): self.running = False

    def _check(self):
        if not PSUTIL_OK: return
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr: continue
                rip  = conn.raddr.ip
                rpt  = conn.raddr.port
                lpt  = conn.laddr.port
                if rip in self.whitelist: continue
                cid = f"{rip}:{rpt}"
                if rip in self.threat_ips:
                    fire_alert(self.config, "CRITICAL",
                        f"KNOWN MALICIOUS IP: {rip}:{rpt} (local port {lpt})")
                if lpt in SUSPICIOUS_PORTS and cid not in self.seen:
                    fire_alert(self.config, "WARN",
                        f"Inbound on {SUSPICIOUS_PORTS[lpt]} port {lpt} from {rip}")
                    self.seen.add(cid)
                if self.config.get("log_all") and cid not in self.seen:
                    fire_alert(self.config, "INFO", f"New conn: {rip}:{rpt}")
                    self.seen.add(cid)
        except Exception: pass

# ============================================================
# MODULE 2 — PORT SCAN DETECTOR (scapy)
# ============================================================
class PortScanDetector:
    def __init__(self, config, iface="eth0"):
        self.config    = config
        self.iface     = iface
        self.ip_ports  = defaultdict(set)
        self.ip_times  = defaultdict(list)
        self.threshold = config.get("alert_threshold", 20)
        self.window    = config.get("scan_window_sec", 10)
        self.running   = False

    def start(self):
        if not SCAPY_OK:
            print(f"{YELLOW}[!]{RESET} Scapy unavailable — port scan detection disabled.")
            return
        self.running = True
        print(f"{GREEN}[✓]{RESET} Port scan detector on {self.iface}.\n")
        sniff(iface=self.iface, prn=self._pkt,
              store=False, stop_filter=lambda _: not self.running)

    def stop(self): self.running = False

    def _pkt(self, pkt):
        if not pkt.haslayer(IP): return
        src = pkt[IP].src
        now = time.time()
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x002:
            self.ip_ports[src].add(pkt[TCP].dport)
            self.ip_times[src].append(now)
            self.ip_times[src] = [t for t in self.ip_times[src] if now-t < self.window]
            if len(self.ip_times[src]) >= self.threshold:
                fire_alert(self.config, "CRITICAL",
                    f"PORT SCAN from {src} — {len(self.ip_ports[src])} ports in {self.window}s")
                self.ip_ports[src].clear(); self.ip_times[src].clear()
        elif pkt.haslayer(ICMP):
            self.ip_times[src].append(now)
            self.ip_times[src] = [t for t in self.ip_times[src] if now-t < self.window]
            if len(self.ip_times[src]) > 50:
                fire_alert(self.config, "WARN",
                    f"ICMP FLOOD from {src} — {len(self.ip_times[src])} pings/{self.window}s")
                self.ip_times[src].clear()

# ============================================================
# MODULE 3 — PORT AUDIT
# ============================================================
def audit_open_ports(config):
    if not PSUTIL_OK:
        print(f"{YELLOW}[!]{RESET} psutil required."); return
    print(f"\n{CYAN}══ OPEN PORTS AUDIT ══{RESET}\n")
    print(f"  {'PORT':<8}{'PROTO':<8}{'STATUS':<14}{'PID':<8}PROCESS")
    print(f"  {'────':<8}{'─────':<8}{'──────':<14}{'───':<8}───────")
    try:
        found = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("LISTEN","ESTABLISHED") or not conn.laddr: continue
            port  = conn.laddr.port
            proto = "TCP" if conn.type == 1 else "UDP"
            pid   = conn.pid or 0
            try:    proc = psutil.Process(pid).name() if pid else "—"
            except: proc = "—"
            flag  = f" {YELLOW}⚠ {SUSPICIOUS_PORTS[port]}{RESET}" if port in SUSPICIOUS_PORTS else ""
            col   = YELLOW if port in SUSPICIOUS_PORTS else GREEN
            print(f"  {col}{port:<8}{RESET}{proto:<8}{conn.status:<14}{pid:<8}{proc}{flag}")
            found.append(port)
        print(f"\n  Total: {len(found)} ports")
        sus = [p for p in found if p in SUSPICIOUS_PORTS]
        if sus: print(f"  {YELLOW}⚠ Suspicious: {sus}{RESET}")
        else:   print(f"  {GREEN}✓ No suspicious ports.{RESET}")
    except PermissionError:
        print(f"{RED}[✗]{RESET} Permission denied — run as root.")

# ============================================================
# MODULE 4 — INTERFACE STATS
# ============================================================
def interface_stats():
    if not PSUTIL_OK: return
    print(f"\n{CYAN}══ NETWORK INTERFACES ══{RESET}\n")
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    io    = psutil.net_io_counters(pernic=True)
    for iface, stat in stats.items():
        status = f"{GREEN}UP{RESET}" if stat.isup else f"{RED}DOWN{RESET}"
        speed  = f"{stat.speed} Mbps" if stat.speed else "N/A"
        ip     = "N/A"
        if iface in addrs:
            for a in addrs[iface]:
                if a.family == socket.AF_INET: ip = a.address
        sent = io[iface].bytes_sent // 1024 if iface in io else 0
        recv = io[iface].bytes_recv // 1024 if iface in io else 0
        print(f"  {WHITE}{iface}{RESET} [{status}] {DIM}{speed}{RESET}")
        print(f"    IP: {CYAN}{ip}{RESET}  ↑ {sent} KB  ↓ {recv} KB\n")

# ============================================================
# MODULE 5 — LIVE SS OUTPUT
# ============================================================
def live_connections():
    print(f"\n{CYAN}══ LIVE CONNECTIONS (ss) ══{RESET}\n")
    try:
        out = subprocess.run(["ss","-tunp"], capture_output=True, text=True).stdout
        for line in out.strip().split("\n"):
            if "ESTAB"  in line: print(f"  {GREEN}{line}{RESET}")
            elif "LISTEN" in line: print(f"  {CYAN}{line}{RESET}")
            else: print(f"  {DIM}{line}{RESET}")
    except FileNotFoundError:
        print(f"{YELLOW}[!]{RESET} ss not found.")

# ============================================================
# MODULE 6 — HTML REPORT
# ============================================================
def generate_report(config):
    if not PSUTIL_OK:
        print(f"{YELLOW}[!]{RESET} psutil required."); return
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    rows     = ""
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr: continue
        port  = conn.laddr.port
        proto = "TCP" if conn.type == 1 else "UDP"
        pid   = conn.pid or 0
        try:    proc = psutil.Process(pid).name() if pid else "—"
        except: proc = "—"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
        flag  = f"⚠ {SUSPICIOUS_PORTS[port]}" if port in SUSPICIOUS_PORTS else ""
        rc    = "suspicious" if port in SUSPICIOUS_PORTS else ""
        rows += f"<tr class='{rc}'><td>{port}</td><td>{proto}</td><td>{conn.status}</td><td>{raddr}</td><td>{pid}</td><td>{proc}</td><td>{flag}</td></tr>\n"

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>NetWatch Report {ts}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d0d;color:#ccc;font-family:'JetBrains Mono',monospace;padding:30px}}
h1{{color:#00b4ff;font-size:26px;margin-bottom:5px}}
h2{{color:#00b4ff;font-size:15px;margin:20px 0 10px;border-bottom:1px solid #222;padding-bottom:6px}}
.meta{{color:#555;font-size:12px;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#111;color:#00b4ff;padding:10px;text-align:left;border-bottom:2px solid #00b4ff}}
td{{padding:8px 10px;border-bottom:1px solid #1a1a1a}}
tr:hover td{{background:#111}}
tr.suspicious td{{color:#f59e0b;font-weight:bold}}
.footer{{margin-top:25px;color:#333;font-size:11px}}
</style></head><body>
<h1>NetWatch — Intrusion Monitor Report</h1>
<div class="meta">Generated: {ts} | Host: {hostname} | by Arunachalam (gojosaturo)</div>
<h2>Active Connections</h2>
<table><tr><th>Port</th><th>Proto</th><th>Status</th><th>Remote</th><th>PID</th><th>Process</th><th>Flag</th></tr>
{rows}</table>
<div class="footer">NetWatch v1.0 | github.com/Arunachalam-gojosaturo/netwatch</div>
</body></html>"""

    with open(REPORT_FILE, "w") as f: f.write(html)
    print(f"{GREEN}[✓]{RESET} Report: {CYAN}{REPORT_FILE}{RESET}")
    print(f"    Open: {DIM}firefox {REPORT_FILE}{RESET}")

# ============================================================
# CONFIGURE
# ============================================================
def configure():
    config = load_config()
    print(f"\n{CYAN}══ CONFIGURE ══{RESET}\n{DIM}  Enter to keep current value{RESET}\n")
    def ask(key, label):
        v = input(f"  {label} [{config.get(key,'')}]: ").strip()
        if v: config[key] = v
    ask("telegram_token",   "Telegram Bot Token")
    ask("telegram_chat_id", "Telegram Chat ID")
    ask("ntfy_topic",       "Ntfy Topic")
    for key, label in [("alert_telegram","Telegram alerts"),("alert_ntfy","Ntfy alerts"),("log_all","Log all conns")]:
        v = input(f"  {label}? (y/n) [{config.get(key)}]: ").strip().lower()
        if v == "y": config[key] = True
        elif v == "n": config[key] = False
    with open(CONFIG_FILE, "w") as f: json.dump(config, f, indent=2)
    print(f"\n{GREEN}[✓]{RESET} Saved.")

# ============================================================
# MAIN MENU
# ============================================================
def main_menu():
    config = load_config()
    setup_logging()
    while True:
        banner()
        print(f"  {BOLD}{CYAN}[ MAIN MENU ]{RESET}\n")
        print(f"  {YELLOW}─── MONITORS ───────────────────────────────{RESET}")
        print(f"  {WHITE}[1]{RESET}  Live Monitor      — connections + scan detection")
        print(f"  {WHITE}[2]{RESET}  Port Audit        — open ports on this system")
        print(f"  {WHITE}[3]{RESET}  Interface Stats   — traffic per interface")
        print(f"  {WHITE}[4]{RESET}  Live Connections  — active TCP/UDP (ss)")
        print(f"\n  {YELLOW}─── INTELLIGENCE ───────────────────────────{RESET}")
        print(f"  {WHITE}[5]{RESET}  Update Threat Intel — refresh malicious IP list")
        print(f"\n  {YELLOW}─── OUTPUT ─────────────────────────────────{RESET}")
        print(f"  {WHITE}[6]{RESET}  Generate HTML Report")
        print(f"  {WHITE}[7]{RESET}  View Log")
        print(f"\n  {YELLOW}─── SETUP ──────────────────────────────────{RESET}")
        print(f"  {WHITE}[8]{RESET}  Configure Alerts (Telegram / Ntfy)")
        print(f"  {WHITE}[9]{RESET}  Install Dependencies")
        print(f"\n  {WHITE}[Q]{RESET}  Quit\n")
        choice = input("  Enter choice: ").strip().upper()

        if choice == "1":
            iface = input("  Interface [eth0/wlan0]: ").strip() or "eth0"
            threat_ips = load_threat_intel()
            print(f"\n{GREEN}[✓]{RESET} Live monitor started. {WHITE}Ctrl+C{RESET} to stop.\n")
            cm = ConnectionMonitor(config, threat_ips)
            sd = PortScanDetector(config, iface)
            t1 = threading.Thread(target=cm.start, daemon=True)
            t2 = threading.Thread(target=sd.start, daemon=True)
            try:
                t1.start()
                if SCAPY_OK: t2.start()
                while True: time.sleep(1)
            except KeyboardInterrupt:
                cm.stop(); sd.stop()
                print(f"\n{YELLOW}[!]{RESET} Monitor stopped.")
            input("  Press Enter...")

        elif choice == "2":
            audit_open_ports(config)
            input("\n  Press Enter...")

        elif choice == "3":
            interface_stats()
            input("\n  Press Enter...")

        elif choice == "4":
            live_connections()
            input("\n  Press Enter...")

        elif choice == "5":
            if THREAT_FILE.exists(): THREAT_FILE.unlink()
            ips = load_threat_intel()
            print(f"{GREEN}[✓]{RESET} {len(ips)} threat IPs loaded.")
            input("\n  Press Enter...")

        elif choice == "6":
            generate_report(config)
            input("\n  Press Enter...")

        elif choice == "7":
            if LOG_FILE.exists(): os.system(f"less {LOG_FILE}")
            else: print(f"{YELLOW}[!]{RESET} No log yet."); input("  Press Enter...")

        elif choice == "8":
            configure(); config = load_config()
            input("\n  Press Enter...")

        elif choice == "9":
            install_deps()
            input("\n  Press Enter...")

        elif choice == "Q":
            print(f"\n  {CYAN}Stay safe. Monitor always.{RESET}\n"); sys.exit(0)
        else:
            print(f"{YELLOW}[!]{RESET} Invalid."); time.sleep(1)

# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch v1.0")
    parser.add_argument("--audit",   action="store_true", help="Quick port audit")
    parser.add_argument("--report",  action="store_true", help="Generate HTML report")
    parser.add_argument("--install", action="store_true", help="Install dependencies")
    parser.add_argument("--iface",   default="eth0")
    args = parser.parse_args()

    setup_dirs()

    if args.install: install_deps(); sys.exit(0)
    if args.audit:   setup_logging(); audit_open_ports(load_config()); sys.exit(0)
    if args.report:  setup_logging(); generate_report(load_config()); sys.exit(0)

    if os.geteuid() != 0:
        print(f"\n{YELLOW}[!]{RESET} Some features need root: {WHITE}sudo python3 netwatch.py{RESET}")
        time.sleep(1)

    main_menu()
