# modules/Intrusion Detection System
"""
NetScope IDS — Intrusion Detection System
Detects: Port Scans, SYN Floods, ARP Spoofing, ICMP Floods, Brute Force
"""

import time
from collections import defaultdict
from threading import Lock


class IntrusionDetector:
    """
    Rule-based Intrusion Detection System.
    Analyzes packet patterns and raises alerts for suspicious activity.
    """

    def __init__(self):
        self._lock = Lock()
        self.alerts = []
        self._alert_callback = None

        # ── Detection Windows (seconds) ──
        self.WINDOW = 10  # analyze last 10 seconds

        # ── Thresholds ──
        self.PORT_SCAN_THRESHOLD   = 15   # unique ports from 1 IP in window
        self.SYN_FLOOD_THRESHOLD   = 50   # SYN packets from 1 IP in window
        self.ICMP_FLOOD_THRESHOLD  = 30   # ICMP packets from 1 IP in window
        self.BRUTE_FORCE_THRESHOLD = 20   # connections to same port from 1 IP
        self.ARP_SPOOF_THRESHOLD   = 2    # different MACs for same IP

        # ── Tracking Data ──
        self._port_scan_tracker  = defaultdict(lambda: defaultdict(set))
        # {time_window: {src_ip: set(ports)}}

        self._syn_flood_tracker  = defaultdict(lambda: defaultdict(int))
        # {time_window: {src_ip: count}}

        self._icmp_flood_tracker = defaultdict(lambda: defaultdict(int))
        # {time_window: {src_ip: count}}

        self._brute_force_tracker = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        # {time_window: {src_ip: {dst_port: count}}}

        self._arp_tracker = defaultdict(set)
        # {ip: set(mac_addresses)}

        # ── Alert Cooldown (prevent spam) ──
        self._alert_cooldown = defaultdict(float)
        self.COOLDOWN_SECONDS = 30

    def set_alert_callback(self, callback):
        """Set function to call when alert is raised"""
        self._alert_callback = callback

    def analyze(self, packet_info):
        """
        Analyze a single packet for intrusion patterns.
        Called for every captured packet.
        """
        try:
            protocol = packet_info.get('protocol', '')
            source   = packet_info.get('source', '')
            dest     = packet_info.get('destination', '')
            dport    = packet_info.get('dport', '-')
            sport    = packet_info.get('sport', '-')
            info     = packet_info.get('info', '')
            raw      = packet_info.get('raw_packet')
            now      = time.time()
            window   = int(now // self.WINDOW)

            with self._lock:
                # ── 1. PORT SCAN DETECTION ──
                if protocol in ('TCP', 'UDP') and dport != '-':
                    self._port_scan_tracker[window][source].add(str(dport))
                    unique_ports = len(self._port_scan_tracker[window][source])
                    if unique_ports >= self.PORT_SCAN_THRESHOLD:
                        self._raise_alert(
                            'CRITICAL',
                            'PORT SCAN DETECTED',
                            f"{source} scanned {unique_ports} unique ports",
                            source, now
                        )

                # ── 2. SYN FLOOD DETECTION ──
                if protocol == 'TCP' and 'S' in str(info):
                    if 'A' not in str(info):  # SYN without ACK
                        self._syn_flood_tracker[window][source] += 1
                        count = self._syn_flood_tracker[window][source]
                        if count >= self.SYN_FLOOD_THRESHOLD:
                            self._raise_alert(
                                'CRITICAL',
                                'SYN FLOOD ATTACK',
                                f"{source} sent {count} SYN packets "
                                f"in {self.WINDOW}s window",
                                source, now
                            )

                # ── 3. ICMP FLOOD DETECTION ──
                if protocol == 'ICMP':
                    self._icmp_flood_tracker[window][source] += 1
                    count = self._icmp_flood_tracker[window][source]
                    if count >= self.ICMP_FLOOD_THRESHOLD:
                        self._raise_alert(
                            'WARNING',
                            'ICMP FLOOD DETECTED',
                            f"{source} sent {count} ICMP packets "
                            f"in {self.WINDOW}s window",
                            source, now
                        )

                # ── 4. BRUTE FORCE DETECTION ──
                if protocol == 'TCP' and dport != '-':
                    if str(dport) in ('22', '21', '23', '3389', '3306'):
                        self._brute_force_tracker[window][source][str(dport)] += 1
                        count = self._brute_force_tracker[window][source][str(dport)]
                        if count >= self.BRUTE_FORCE_THRESHOLD:
                            svc = {'22': 'SSH', '21': 'FTP', '23': 'Telnet',
                                   '3389': 'RDP', '3306': 'MySQL'}
                            service = svc.get(str(dport), f'Port {dport}')
                            self._raise_alert(
                                'CRITICAL',
                                f'BRUTE FORCE on {service}',
                                f"{source} made {count} attempts "
                                f"to {service} (port {dport})",
                                source, now
                            )

                # ── 5. ARP SPOOFING DETECTION ──
                if protocol == 'ARP' and raw:
                    try:
                        from scapy.layers.l2 import ARP
                        if raw.haslayer(ARP) and raw[ARP].op == 2:
                            arp_ip  = raw[ARP].psrc
                            arp_mac = raw[ARP].hwsrc
                            if arp_ip and arp_mac:
                                self._arp_tracker[arp_ip].add(arp_mac)
                                if len(self._arp_tracker[arp_ip]) >= self.ARP_SPOOF_THRESHOLD:
                                    macs = ', '.join(
                                        list(self._arp_tracker[arp_ip])[:3]
                                    )
                                    self._raise_alert(
                                        'CRITICAL',
                                        'ARP SPOOFING DETECTED',
                                        f"IP {arp_ip} has multiple MACs: {macs}",
                                        arp_ip, now
                                    )
                    except Exception:
                        pass

                # ── Cleanup old windows ──
                self._cleanup_old_windows(window)

        except Exception as e:
            pass  # Don't crash the sniffer for IDS errors

    def _raise_alert(self, severity, alert_type, message, source_ip, timestamp):
        """Create an alert if not in cooldown"""
        cooldown_key = f"{alert_type}_{source_ip}"
        now = time.time()

        if now - self._alert_cooldown[cooldown_key] < self.COOLDOWN_SECONDS:
            return  # Still in cooldown

        self._alert_cooldown[cooldown_key] = now

        alert = {
            'timestamp': time.strftime('%H:%M:%S'),
            'severity':  severity,
            'type':      alert_type,
            'message':   message,
            'source_ip': source_ip,
            'epoch':     now,
        }

        self.alerts.append(alert)

        # Keep only last 200 alerts
        if len(self.alerts) > 200:
            self.alerts = self.alerts[-200:]

        # Fire callback
        if self._alert_callback:
            self._alert_callback(alert)

    def _cleanup_old_windows(self, current_window):
        """Remove tracking data older than 2 windows"""
        cutoff = current_window - 2

        for tracker in [self._port_scan_tracker,
                        self._syn_flood_tracker,
                        self._icmp_flood_tracker,
                        self._brute_force_tracker]:
            old_keys = [k for k in tracker if k < cutoff]
            for k in old_keys:
                del tracker[k]

    def get_alert_summary(self):
        """Return count of alerts by severity"""
        summary = {'CRITICAL': 0, 'WARNING': 0, 'INFO': 0}
        for a in self.alerts:
            sev = a.get('severity', 'INFO')
            if sev in summary:
                summary[sev] += 1
        return summary

    def get_recent_alerts(self, count=20):
        """Return the most recent alerts"""
        return self.alerts[-count:]

    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()
        self._alert_cooldown.clear()