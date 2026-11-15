# modules/statistics.py
"""
Statistics and chart generation module for NetScope
Supports both Dark and Light themes
"""

import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import tkinter as tk


# ══════════════════════════════════════════════════════════
#   THEME PALETTES FOR CHARTS
# ══════════════════════════════════════════════════════════

PALETTES = {
    'dark': {
        'bg':         '#0d1117',   # window + figure background
        'panel':      '#161b22',   # chart area background
        'text':       '#c9d1d9',
        'grid':       '#21262d',
        'accent':     '#58a6ff',
        'bar_bg':     '#21262d',   # stats bar background
        'bar_fg':     '#8b949e',   # stats bar text
        'close_bg':   '#21262d',
        'close_fg':   '#f85149',
        'close_act':  '#f85149',
        'pie_text':   '#0d1117',   # % text on pie slices
        'colors': [
            '#58a6ff', '#3fb950', '#d29922', '#f78166',
            '#bc8cff', '#39d353', '#ff7b72', '#79c0ff',
        ],
    },
    'light': {
        'bg':         '#ffffff',   # WHITE background
        'panel':      '#ffffff',
        'text':       '#1f2328',   # dark text for readability
        'grid':       '#d0d7de',
        'accent':     '#0969da',
        'bar_bg':     '#eaeef2',
        'bar_fg':     '#57606a',
        'close_bg':   '#eaeef2',
        'close_fg':   '#cf222e',
        'close_act':  '#cf222e',
        'pie_text':   '#ffffff',
        'colors': [
            '#0969da', '#1a7f37', '#bf8700', '#cf222e',
            '#8250df', '#2da44e', '#fa4549', '#218bff',
        ],
    },
}


def apply_chart_style(P):
    """Apply matplotlib global style using the given palette"""
    plt.rcParams.update({
        'figure.facecolor':  P['bg'],
        'axes.facecolor':    P['panel'],
        'axes.edgecolor':    P['grid'],
        'axes.labelcolor':   P['text'],
        'xtick.color':       P['text'],
        'ytick.color':       P['text'],
        'text.color':        P['text'],
        'grid.color':        P['grid'],
        'legend.facecolor':  P['panel'],
        'legend.edgecolor':  P['grid'],
        'legend.labelcolor': P['text'],
    })


def show_statistics_window(parent, stats, captured_packets,
                           theme='dark'):
    """
    Open statistics window with 4 charts.
    theme: 'dark' or 'light'
    """
    P = PALETTES.get(theme, PALETTES['dark'])
    apply_chart_style(P)

    win = tk.Toplevel(parent)
    win.title("📊 NetScope — Traffic Statistics")
    win.geometry("1100x750")
    win.configure(bg=P['bg'])
    win.grab_set()

    # Title label
    tk.Label(win,
             text="📊  NETWORK TRAFFIC STATISTICS",
             font=('Consolas', 15, 'bold'),
             bg=P['bg'], fg=P['accent']).pack(pady=(12, 0))

    # Stats bar
    s = stats
    bar_text = (
        f"  Total: {s.get('total_packets', 0)}  │  "
        f"Bytes: {s.get('total_bytes_fmt', '0 B')}  │  "
        f"TCP: {s.get('tcp_count', 0)}  │  "
        f"UDP: {s.get('udp_count', 0)}  │  "
        f"ICMP: {s.get('icmp_count', 0)}  │  "
        f"DNS: {s.get('dns_count', 0)}  │  "
        f"ARP: {s.get('arp_count', 0)}  "
    )
    tk.Label(win, text=bar_text,
             font=('Consolas', 9),
             bg=P['bar_bg'], fg=P['bar_fg'],
             anchor='w', padx=10).pack(fill=tk.X, padx=15, pady=8)

    # Figure
    fig = Figure(figsize=(14, 9), facecolor=P['bg'])
    gs = gridspec.GridSpec(2, 2, figure=fig,
                           hspace=0.45, wspace=0.35,
                           left=0.08, right=0.97,
                           top=0.93, bottom=0.08)

    ax1 = fig.add_subplot(gs[0, 0])
    _draw_protocol_pie(ax1, stats, P)

    ax2 = fig.add_subplot(gs[0, 1])
    _draw_top_ips(ax2, stats, P)

    ax3 = fig.add_subplot(gs[1, 0])
    _draw_pps(ax3, stats, P)

    ax4 = fig.add_subplot(gs[1, 1])
    _draw_packet_sizes(ax4, stats, P)

    canvas = FigureCanvasTkAgg(fig, master=win)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True,
                                padx=15, pady=(0, 15))

    # Close button
    tk.Button(win, text="✕  Close",
              font=('Consolas', 10, 'bold'),
              bg=P['close_bg'], fg=P['close_fg'],
              activebackground=P['close_act'],
              activeforeground='white',
              bd=0, padx=20, pady=8,
              command=win.destroy).pack(pady=(0, 10))


# ══════════════════════════════════════════════════════════
#   INDIVIDUAL CHARTS
# ══════════════════════════════════════════════════════════

def _no_data(ax, message, title, P):
    ax.text(0.5, 0.5, message,
            ha='center', va='center',
            color=P['text'], fontsize=12,
            transform=ax.transAxes)
    ax.set_title(title, color=P['text'],
                 fontsize=11, fontweight='bold', pad=10)


def _draw_protocol_pie(ax, stats, P):
    protocols = {
        'TCP':   stats.get('tcp_count', 0),
        'UDP':   stats.get('udp_count', 0),
        'ICMP':  stats.get('icmp_count', 0),
        'ARP':   stats.get('arp_count', 0),
        'DNS':   stats.get('dns_count', 0),
        'HTTP':  stats.get('http_count', 0),
        'HTTPS': stats.get('https_count', 0),
        'Other': stats.get('other_count', 0),
    }
    data = {k: v for k, v in protocols.items() if v > 0}
    labels = list(data.keys())
    values = list(data.values())

    if not values:
        _no_data(ax, 'No Data', 'Protocol Distribution', P)
        return

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct='%1.1f%%',
        colors=P['colors'][:len(labels)],
        startangle=90,
        pctdistance=0.8,
        wedgeprops=dict(edgecolor=P['bg'], linewidth=1.5)
    )
    for t in texts:
        t.set_color(P['text'])
        t.set_fontsize(8)
    for at in autotexts:
        at.set_color(P['pie_text'])
        at.set_fontsize(7)
        at.set_fontweight('bold')

    ax.set_title('Protocol Distribution', color=P['text'],
                 fontsize=11, fontweight='bold', pad=10)


def _draw_top_ips(ax, stats, P):
    ip_sources = stats.get('ip_sources', {})
    top = sorted(ip_sources.items(),
                 key=lambda x: x[1], reverse=True)[:8]

    if not top:
        _no_data(ax, 'No IP Data', 'Top Source IPs', P)
        return

    ips, counts = zip(*top)
    short_ips = [ip[-15:] if len(ip) > 15 else ip for ip in ips]
    y_pos = list(range(len(short_ips)))

    bars = ax.barh(y_pos, list(counts),
                   color=P['colors'][0], alpha=0.85,
                   edgecolor=P['bg'], height=0.6)

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                str(count), va='center',
                color=P['text'], fontsize=7)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(short_ips, fontsize=7)
    ax.set_xlabel('Packet Count', fontsize=9)
    ax.set_title('Top Source IPs', color=P['text'],
                 fontsize=11, fontweight='bold', pad=10)
    ax.grid(axis='x', alpha=0.3)
    ax.set_facecolor(P['panel'])


def _draw_pps(ax, stats, P):
    pps_data = stats.get('pps_data', {})

    if not pps_data:
        _no_data(ax, 'No Timeline Data', 'Packets Per Second', P)
        return

    times = sorted(pps_data.keys())
    values = [pps_data[t] for t in times]

    ax.plot(times, values,
            color=P['colors'][1], linewidth=2, zorder=3)
    ax.fill_between(times, values,
                    color=P['colors'][1], alpha=0.15)
    ax.set_xlabel('Time (seconds)', fontsize=9)
    ax.set_ylabel('Packets/sec', fontsize=9)
    ax.set_title('Packets Per Second', color=P['text'],
                 fontsize=11, fontweight='bold', pad=10)
    ax.grid(alpha=0.3)
    ax.set_facecolor(P['panel'])


def _draw_packet_sizes(ax, stats, P):
    sizes = stats.get('packet_sizes', [])

    if not sizes:
        _no_data(ax, 'No Size Data', 'Packet Size Distribution', P)
        return

    ax.hist(sizes, bins=30,
            color=P['colors'][3], alpha=0.8,
            edgecolor=P['bg'], linewidth=0.5)
    ax.set_xlabel('Packet Size (bytes)', fontsize=9)
    ax.set_ylabel('Frequency', fontsize=9)
    ax.set_title('Packet Size Distribution', color=P['text'],
                 fontsize=11, fontweight='bold', pad=10)
    ax.grid(alpha=0.3)
    ax.set_facecolor(P['panel'])

    avg = sum(sizes) / len(sizes)
    ax.axvline(avg, color=P['colors'][0],
               linestyle='--', linewidth=1.5,
               label=f'Avg: {avg:.0f}B')
    ax.legend(fontsize=8)