# modules/decoder.py
"""
Protocol decoder module for NetScope
Handles deep packet inspection and protocol identification
"""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.all import conf


def get_protocol(packet):
    """
    Identify the highest-level protocol in the packet
    Returns protocol name as string
    """
    try:
        # Check ARP first (Layer 2)
        if packet.haslayer(ARP):
            return "ARP"

        # Check DNS (can be over TCP or UDP)
        if packet.haslayer(DNS):
            return "DNS"

        # Check TCP-based protocols
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if sport == 443 or dport == 443:
                return "HTTPS/TLS"
            elif sport == 80 or dport == 80:
                return "HTTP"
            elif sport == 22 or dport == 22:
                return "SSH"
            elif sport == 21 or dport == 21:
                return "FTP"
            elif sport == 25 or dport == 25:
                return "SMTP"
            elif sport == 3306 or dport == 3306:
                return "MySQL"
            elif sport == 3389 or dport == 3389:
                return "RDP"
            else:
                return "TCP"

        # Check UDP-based protocols
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport

            if sport == 53 or dport == 53:
                return "DNS"
            elif sport == 67 or dport == 67:
                return "DHCP"
            elif sport == 68 or dport == 68:
                return "DHCP"
            elif sport == 123 or dport == 123:
                return "NTP"
            else:
                return "UDP"

        # Check ICMP
        if packet.haslayer(ICMP):
            return "ICMP"

        return "OTHER"

    except Exception:
        return "OTHER"


def get_packet_summary(packet, protocol):
    """
    Generate a one-line info summary for the packet
    """
    info = ""
    try:
        if protocol == "TCP" or protocol in ["HTTP", "HTTPS/TLS", "SSH", "FTP", "SMTP"]:
            if packet.haslayer(TCP):
                flags = str(packet[TCP].flags)
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = f"{sport} → {dport}  [{flags}]  Seq={packet[TCP].seq}  Win={packet[TCP].window}"

        elif protocol == "UDP":
            if packet.haslayer(UDP):
                info = f"{packet[UDP].sport} → {packet[UDP].dport}  Len={packet[UDP].len}"

        elif protocol == "DNS":
            if packet.haslayer(DNSQR):
                try:
                    qname = packet[DNSQR].qname.decode() if packet[DNSQR].qname else "?"
                    info = f"Query: {qname}"
                except Exception:
                    info = "DNS Query"
            elif packet.haslayer(DNSRR):
                info = "DNS Response"
            else:
                info = "DNS Packet"

        elif protocol == "ARP":
            if packet.haslayer(ARP):
                if packet[ARP].op == 1:
                    info = f"Who has {packet[ARP].pdst}?  Tell {packet[ARP].psrc}"
                elif packet[ARP].op == 2:
                    info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
                else:
                    info = f"ARP op={packet[ARP].op}"

        elif protocol == "ICMP":
            if packet.haslayer(ICMP):
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    8: "Echo Request (Ping)",
                    11: "Time Exceeded",
                    5: "Redirect"
                }
                t = packet[ICMP].type
                info = icmp_types.get(t, f"Type={t}  Code={packet[ICMP].code}")

        else:
            info = f"Packet length: {len(packet)} bytes"

    except Exception as e:
        info = f"[Parse Error] Length={len(packet)}"

    return info


def get_source_dest(packet):
    """
    Extract source and destination addresses
    Returns (source, destination) tuple
    """
    try:
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        elif packet.haslayer(ARP):
            return packet[ARP].psrc, packet[ARP].pdst
        elif packet.haslayer(Ether):
            return packet[Ether].src, packet[Ether].dst
    except Exception:
        pass
    return "N/A", "N/A"


def get_full_details(packet_info):
    """
    Get complete layer-by-layer details of a packet
    Returns formatted string for display
    """
    packet = packet_info.get('raw_packet')
    if not packet:
        return "No packet data available."

    lines = []

    # ── Frame Info ──
    lines.append("┌─────────────────────────────────────────────────┐")
    lines.append(f"│  FRAME #{packet_info.get('number', '?')}                                      ")
    lines.append("├─────────────────────────────────────────────────┤")
    lines.append(f"  Arrival Time  : {packet_info.get('timestamp', 'N/A')}")
    lines.append(f"  Frame Length  : {packet_info.get('length', 0)} bytes")
    lines.append(f"  Protocol      : {packet_info.get('protocol', 'N/A')}")
    lines.append("")

    # ── Ethernet Layer ──
    if packet.haslayer(Ether):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  ETHERNET II  (Layer 2 - Data Link)              │")
        lines.append("└─────────────────────────────────────────────────┘")
        lines.append(f"  Source MAC     : {packet[Ether].src}")
        lines.append(f"  Destination MAC: {packet[Ether].dst}")
        lines.append(f"  EtherType      : {hex(packet[Ether].type)}")
        lines.append("")

    # ── ARP Layer ──
    if packet.haslayer(ARP):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  ARP  (Address Resolution Protocol)              │")
        lines.append("└─────────────────────────────────────────────────┘")
        op_map = {1: "Request (Who has?)", 2: "Reply (Is at)"}
        lines.append(f"  Operation      : {op_map.get(packet[ARP].op, packet[ARP].op)}")
        lines.append(f"  Sender MAC     : {packet[ARP].hwsrc}")
        lines.append(f"  Sender IP      : {packet[ARP].psrc}")
        lines.append(f"  Target MAC     : {packet[ARP].hwdst}")
        lines.append(f"  Target IP      : {packet[ARP].pdst}")
        lines.append("")

    # ── IP Layer ──
    if packet.haslayer(IP):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  INTERNET PROTOCOL  (Layer 3 - Network)          │")
        lines.append("└─────────────────────────────────────────────────┘")
        lines.append(f"  Version        : IPv{packet[IP].version}")
        lines.append(f"  Header Length  : {packet[IP].ihl * 4} bytes")
        lines.append(f"  Total Length   : {packet[IP].len} bytes")
        lines.append(f"  TTL            : {packet[IP].ttl}")
        lines.append(f"  Protocol       : {packet[IP].proto}")
        lines.append(f"  Checksum       : {hex(packet[IP].chksum)}")
        lines.append(f"  Source IP      : {packet[IP].src}")
        lines.append(f"  Destination IP : {packet[IP].dst}")
        lines.append("")

    # ── ICMP Layer ──
    if packet.haslayer(ICMP):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  ICMP  (Internet Control Message Protocol)       │")
        lines.append("└─────────────────────────────────────────────────┘")
        icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                      8: "Echo Request", 11: "Time Exceeded"}
        type_name = icmp_types.get(packet[ICMP].type, "Unknown")
        lines.append(f"  Type           : {packet[ICMP].type}  ({type_name})")
        lines.append(f"  Code           : {packet[ICMP].code}")
        lines.append(f"  Checksum       : {hex(packet[ICMP].chksum)}")
        lines.append("")

    # ── TCP Layer ──
    if packet.haslayer(TCP):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  TCP  (Transmission Control Protocol - Layer 4)  │")
        lines.append("└─────────────────────────────────────────────────┘")
        lines.append(f"  Source Port    : {packet[TCP].sport}")
        lines.append(f"  Dest Port      : {packet[TCP].dport}")
        lines.append(f"  Sequence No.   : {packet[TCP].seq}")
        lines.append(f"  Ack Number     : {packet[TCP].ack}")
        lines.append(f"  Flags          : {packet[TCP].flags}")
        lines.append(f"  Window Size    : {packet[TCP].window}")
        lines.append(f"  Checksum       : {hex(packet[TCP].chksum)}")
        lines.append(f"  Urgent Ptr     : {packet[TCP].urgptr}")
        lines.append("")

    # ── UDP Layer ──
    if packet.haslayer(UDP):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  UDP  (User Datagram Protocol - Layer 4)         │")
        lines.append("└─────────────────────────────────────────────────┘")
        lines.append(f"  Source Port    : {packet[UDP].sport}")
        lines.append(f"  Dest Port      : {packet[UDP].dport}")
        lines.append(f"  Length         : {packet[UDP].len}")
        lines.append(f"  Checksum       : {hex(packet[UDP].chksum)}")
        lines.append("")

    # ── DNS Layer ──
    if packet.haslayer(DNS):
        lines.append("┌─────────────────────────────────────────────────┐")
        lines.append("│  DNS  (Domain Name System)                       │")
        lines.append("└─────────────────────────────────────────────────┘")
        lines.append(f"  Transaction ID : {packet[DNS].id}")
        lines.append(f"  QR Flag        : {'Response' if packet[DNS].qr else 'Query'}")
        lines.append(f"  Questions      : {packet[DNS].qdcount}")
        lines.append(f"  Answers        : {packet[DNS].ancount}")
        if packet.haslayer(DNSQR):
            try:
                qname = packet[DNSQR].qname.decode()
                lines.append(f"  Query Name     : {qname}")
                lines.append(f"  Query Type     : {packet[DNSQR].qtype}")
            except Exception:
                pass
        lines.append("")

    # ── Raw Hex Dump ──
    lines.append("┌─────────────────────────────────────────────────┐")
    lines.append("│  HEX DUMP                                        │")
    lines.append("└─────────────────────────────────────────────────┘")
    raw = bytes(packet)
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:04x}  {hex_str:<48}  {ascii_str}")
    lines.append("")

    return '\n'.join(lines)