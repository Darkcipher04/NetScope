# modules/sniffer.py
"""
Core packet sniffing engine for NetScope
Handles packet capture, processing and statistics
"""

import threading
import time
from collections import defaultdict
from scapy.all import sniff, wrpcap, conf

from modules.decoder import get_protocol, get_packet_summary, get_source_dest
from modules.utils import get_timestamp, format_bytes
from modules.ids import IntrusionDetector # New
from modules.bandwidth import BandwidthMonitor # New


class NetScopeSniffer:
    """
    Main packet capture and analysis engine
    """

    def __init__(self):
        self.captured_packets = []
        self.is_sniffing = False
        self._sniff_thread = None
        self._start_time = None
        self._packet_callback = None
        self._stats_callback = None
        self._lock = threading.Lock()

        # NEW : IDS & BANDWIDTH
        self.ids = IntrusionDetector()
        self.bandwidth = BandwidthMonitor()

        # Initialize statistics
        self._reset_stats()

    def _reset_stats(self):
        """Reset all capture statistics"""
        self.stats = {
            'total_packets':    0,
            'total_bytes':      0,
            'tcp_count':        0,
            'udp_count':        0,
            'icmp_count':       0,
            'arp_count':        0,
            'dns_count':        0,
            'http_count':       0,
            'https_count':      0,
            'other_count':      0,
            'ip_sources':       defaultdict(int),
            'ip_destinations':  defaultdict(int),
            'ports':            defaultdict(int),
            'packet_sizes':     [],
            'pps_data':         defaultdict(int),  # packets per second
            'bps_data':         defaultdict(int),  # bytes per second
            'protocol_timeline': [],
        }
        # NEW
        self.ids.clear_alerts()
        self.bandwidth = BandwidthMonitor()

    def _process_packet(self, packet):
        """
        Called for every captured packet.
        Extracts info, updates stats, fires callback.
        """
        if not self.is_sniffing:
            return

        try:
            timestamp = get_timestamp()
            time_offset = round(time.time() - self._start_time, 4)
            pkt_len = len(packet)

            # Get protocol and addresses
            protocol = get_protocol(packet)
            source, destination = get_source_dest(packet)

            # Build port info
            sport, dport = self._get_ports(packet, protocol)

            # Build packet info dict
            packet_info = {
                'number':      self.stats['total_packets'] + 1,
                'timestamp':   timestamp,
                'time_offset': time_offset,
                'source':      source,
                'destination': destination,
                'protocol':    protocol,
                'length':      pkt_len,
                'sport':       sport,
                'dport':       dport,
                'info':        get_packet_summary(packet, protocol),
                'raw_packet':  packet,
            }

            # Update stats thread-safely
            with self._lock:
                self._update_stats(protocol, pkt_len, source,
                                   destination, sport, dport, time_offset)
                self.captured_packets.append(packet_info)

            # NEW: Feed to IDS
            self.ids.analyze(packet_info)

            # NEW: Feed to Bandwidth Monitor
            is_incoming = (destination != 'N/A')
            self.bandwidth.add_packet(pkt_len, is_incoming)

            # Fire GUI callback
            if self._packet_callback:
                self._packet_callback(packet_info)

        except Exception as e:
            print(f"[Sniffer] Packet processing error: {e}")

    def _get_ports(self, packet, protocol):
        """Extract sport and dport from packet"""
        from scapy.layers.inet import TCP, UDP
        try:
            if packet.haslayer(TCP):
                return packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                return packet[UDP].sport, packet[UDP].dport
        except Exception:
            pass
        return '-', '-'

    def _update_stats(self, protocol, pkt_len, source,
                      destination, sport, dport, time_offset):
        """Update all statistics counters"""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += pkt_len
        self.stats['packet_sizes'].append(pkt_len)

        # Protocol counts
        proto_map = {
            'TCP': 'tcp_count', 'UDP': 'udp_count',
            'ICMP': 'icmp_count', 'ARP': 'arp_count',
            'DNS': 'dns_count', 'HTTP': 'http_count',
            'HTTPS/TLS': 'https_count',
        }
        key = proto_map.get(protocol, 'other_count')
        self.stats[key] += 1

        # IP tracking
        if source != 'N/A':
            self.stats['ip_sources'][source] += 1
        if destination != 'N/A':
            self.stats['ip_destinations'][destination] += 1

        # Port tracking
        if dport != '-':
            try:
                self.stats['ports'][int(dport)] += 1
            except Exception:
                pass

        # Time-based data
        second = int(time_offset)
        self.stats['pps_data'][second] += 1
        self.stats['bps_data'][second] += pkt_len

        # Protocol timeline
        self.stats['protocol_timeline'].append({
            'time': time_offset,
            'protocol': protocol
        })

    def start(self, interface=None, bpf_filter="", packet_cb=None):
        """
        Start packet capture.
        interface  : network interface name (None = default)
        bpf_filter : BPF filter string
        packet_cb  : callback(packet_info) called for each packet
        """
        if self.is_sniffing:
            return False, "Already sniffing"

        self.is_sniffing = True
        self._start_time = time.time()
        self._packet_callback = packet_cb
        self.captured_packets = []
        self._reset_stats()

        iface = interface if interface and interface != "default" else None

        def _sniff():
            try:
                sniff(
                    iface=iface,
                    filter=bpf_filter if bpf_filter else None,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda x: not self.is_sniffing
                )
            except Exception as e:
                print(f"[Sniffer] Error: {e}")
                self.is_sniffing = False

        self._sniff_thread = threading.Thread(
            target=_sniff,
            daemon=True,
            name="NetScope-Sniffer"
        )
        self._sniff_thread.start()
        return True, "Started"

    def stop(self):
        """Stop packet capture"""
        self.is_sniffing = False

    def get_packet_details(self, index):
        """Get full details for packet at given index"""
        from modules.decoder import get_full_details
        try:
            if 0 <= index < len(self.captured_packets):
                return get_full_details(self.captured_packets[index])
        except Exception as e:
            return f"Error loading packet details: {e}"
        return "Select a packet to view details."

    def export_txt(self, filepath):
        """Export captured packets to text file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 100 + "\n")
                f.write("  NetScope - Network Analyzer & Packet Sniffer\n")
                f.write(f"  Exported: {get_timestamp()}\n")
                f.write(f"  Total Packets: {self.stats['total_packets']}\n")
                f.write(f"  Total Bytes: {format_bytes(self.stats['total_bytes'])}\n")
                f.write("=" * 100 + "\n\n")

                header = (f"{'No.':<6} {'Time':<14} {'Source':<18} "
                         f"{'Destination':<18} {'Protocol':<10} "
                         f"{'Length':<8} Info\n")
                f.write(header)
                f.write("-" * 100 + "\n")

                for pkt in self.captured_packets:
                    line = (f"{pkt['number']:<6} {pkt['timestamp']:<14} "
                           f"{pkt['source']:<18} {pkt['destination']:<18} "
                           f"{pkt['protocol']:<10} {pkt['length']:<8} "
                           f"{pkt['info']}\n")
                    f.write(line)

            return True, filepath
        except Exception as e:
            return False, str(e)

    def export_pcap(self, filepath):
        """Export captured packets to PCAP format"""
        try:
            packets = [p['raw_packet'] for p in self.captured_packets]
            if packets:
                wrpcap(filepath, packets)
            return True, filepath
        except Exception as e:
            return False, str(e)

    def get_stats_summary(self):
        """Return formatted statistics summary"""
        s = self.stats
        return {
            'total':   s['total_packets'],
            'bytes':   format_bytes(s['total_bytes']),
            'tcp':     s['tcp_count'],
            'udp':     s['udp_count'],
            'icmp':    s['icmp_count'],
            'arp':     s['arp_count'],
            'dns':     s['dns_count'],
            'http':    s['http_count'],
            'https':   s['https_count'],
            'other':   s['other_count'],
        }