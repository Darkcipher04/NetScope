# modules/utils.py — NetScope v2.0 helpers

import time
import datetime

# ── Protocol tag colours ──────────────────────────────────────────
PROTOCOL_TAG_COLORS_DARK = {
    "TCP":   {"bg": "#1a3a2a", "fg": "#4ade80"},
    "UDP":   {"bg": "#1a2a3a", "fg": "#60a5fa"},
    "HTTP":  {"bg": "#3a2a1a", "fg": "#fb923c"},
    "HTTPS": {"bg": "#2a1a3a", "fg": "#c084fc"},
    "DNS":   {"bg": "#1a3a3a", "fg": "#2dd4bf"},
    "ARP":   {"bg": "#3a3a1a", "fg": "#facc15"},
    "ICMP":  {"bg": "#3a1a2a", "fg": "#f472b6"},
    "SSH":   {"bg": "#2a2a2a", "fg": "#a8a29e"},
    "FTP":   {"bg": "#1a2a2a", "fg": "#67e8f9"},
    "SMTP":  {"bg": "#2a1a2a", "fg": "#d946ef"},
    "OTHER": {"bg": "#1e1e2e", "fg": "#94a3b8"},
}

PROTOCOL_TAG_COLORS_LIGHT = {
    "TCP":   {"bg": "#dcfce7", "fg": "#166534"},
    "UDP":   {"bg": "#dbeafe", "fg": "#1e40af"},
    "HTTP":  {"bg": "#ffedd5", "fg": "#9a3412"},
    "HTTPS": {"bg": "#f3e8ff", "fg": "#6b21a8"},
    "DNS":   {"bg": "#ccfbf1", "fg": "#115e59"},
    "ARP":   {"bg": "#fef9c3", "fg": "#854d0e"},
    "ICMP":  {"bg": "#fce7f3", "fg": "#9d174d"},
    "SSH":   {"bg": "#f5f5f4", "fg": "#44403c"},
    "FTP":   {"bg": "#cffafe", "fg": "#155e75"},
    "SMTP":  {"bg": "#fae8ff", "fg": "#86198f"},
    "OTHER": {"bg": "#f1f5f9", "fg": "#475569"},
}

# Default (what main.py imports as PROTOCOL_TAG_COLORS)
PROTOCOL_TAG_COLORS = PROTOCOL_TAG_COLORS_DARK

# ── BPF filter presets  (dict as main.py expects) ─────────────────
BPF_FILTER_EXAMPLES = {
    "All Traffic":    "",
    "TCP only":       "tcp",
    "UDP only":       "udp",
    "HTTP":           "tcp port 80",
    "HTTPS":          "tcp port 443",
    "DNS":            "udp port 53",
    "ICMP / Ping":    "icmp",
    "ARP":            "arp",
    "SSH":            "tcp port 22",
    "No Broadcast":   "not broadcast and not multicast",
}

# ── Helpers ───────────────────────────────────────────────────────
def get_timestamp() -> str:
    t = time.time()
    ms = int((t - int(t)) * 1000)
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{ms:03d}"

def format_bytes(b) -> str:
    try:
        b = float(b)
    except Exception:
        return "0 B"
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def readable_size(b) -> str:
    return format_bytes(b)

def get_date_filename() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def get_network_interfaces():
    """Return list of dicts [{'name': 'Wi-Fi', 'display': 'Wi-Fi (up)'}, ...]"""
    out = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, st in stats.items():
            status = "up" if st.isup else "down"
            ip = ""
            if name in addrs:
                for a in addrs[name]:
                    if a.family.name in ("AF_INET",):
                        ip = f" · {a.address}"
                        break
            out.append({"name": name,
                        "display": f"{name} ({status}){ip}"})
    except Exception:
        for n in ("Wi-Fi", "Ethernet", "eth0", "wlan0"):
            out.append({"name": n, "display": n})
    return out

def short_id(pkt_id: int) -> str:
    return f"#{pkt_id:05d}"