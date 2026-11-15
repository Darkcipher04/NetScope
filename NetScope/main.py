# main.py
"""
NetScope v2.0 — Network Analyzer & Packet Sniffer
Features: IDS, Bandwidth Monitor, Alerts, GeoIP, Theme Toggle
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.scrolledtext as scrolledtext
import threading
import os
import sys

from modules.sniffer import NetScopeSniffer
from modules.utils import (get_network_interfaces, get_date_filename,
                            PROTOCOL_TAG_COLORS_DARK, PROTOCOL_TAG_COLORS_LIGHT,
                            BPF_FILTER_EXAMPLES, format_bytes)
from modules.statistics import show_statistics_window
from modules.ids import IntrusionDetector
from modules.alerts import (create_alert_tab, add_alert_to_text,
                             show_alert_popup)
from modules.geoip import show_geoip_window
from modules.bandwidth import BandwidthMonitor

# Auto-create folders
os.makedirs('exports', exist_ok=True)
os.makedirs('modules', exist_ok=True)


# ══════════════════════════════════════════════════════════
#   THEME DEFINITIONS
# ══════════════════════════════════════════════════════════

THEMES = {
    'dark': {
        'bg':       '#0d1117',
        'panel':    '#161b22',
        'border':   '#30363d',
        'surface':  '#21262d',
        'hover':    '#2d333b',
        'text':     '#c9d1d9',
        'muted':    '#8b949e',
        'accent':   '#58a6ff',
        'green':    '#3fb950',
        'red':      '#f85149',
        'yellow':   '#d29922',
        'purple':   '#bc8cff',
        'orange':   '#e3b341',
        'cyan':     '#39d353',
        'hex_fg':   '#3fb950',
        'detail_fg':'#a8dadc',
    },
    'light': {
        'bg':       '#f6f8fa',
        'panel':    '#ffffff',
        'border':   '#d0d7de',
        'surface':  '#eaeef2',
        'hover':    '#d0d7de',
        'text':     '#1f2328',
        'muted':    '#656d76',
        'accent':   '#0969da',
        'green':    '#1a7f37',
        'red':      '#cf222e',
        'yellow':   '#9a6700',
        'purple':   '#8250df',
        'orange':   '#bc4c00',
        'cyan':     '#1a7f37',
        'hex_fg':   '#1a7f37',
        'detail_fg':'#0969da',
    }
}

FONTS = {
    'title':   ('Consolas', 16, 'bold'),
    'heading': ('Consolas', 11, 'bold'),
    'body':    ('Consolas', 10),
    'small':   ('Consolas', 9),
    'mono':    ('Consolas', 10),
}


# ══════════════════════════════════════════════════════════
#   MAIN APPLICATION CLASS
# ══════════════════════════════════════════════════════════

class NetScopeApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.sniffer = NetScopeSniffer()
        self.is_capturing = False
        self._interfaces = get_network_interfaces()
        self._all_packets_shown = []
        self._selected_index = None

        # Theme state
        self._current_theme = 'dark'
        self.C = THEMES['dark']

        self._buttons = []  # Keep track of custom buttons for theme switching

        # IDS alert callback
        self.sniffer.ids.set_alert_callback(self._on_ids_alert)

        self._setup_window()
        self._build_styles()
        self._build_ui()
        self._start_live_update()

    def _setup_window(self):
        self.root.title("NetScope v2.0  ·  Network Analyzer & Packet Sniffer")
        self.root.geometry("1400x860")
        self.root.minsize(1100, 700)
        self.root.configure(bg=self.C['bg'])
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 1400) // 2
        y = (self.root.winfo_screenheight() - 860) // 2
        self.root.geometry(f"1400x860+{x}+{y}")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ────────────────────────────────────────────────
    #   STYLES
    # ────────────────────────────────────────────────

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        C = self.C

        style.configure('Packets.Treeview',
                        background=C['panel'],
                        foreground=C['text'],
                        fieldbackground=C['panel'],
                        borderwidth=0, rowheight=24,
                        font=FONTS['small'])
        style.configure('Packets.Treeview.Heading',
                        background=C['surface'],
                        foreground=C['accent'],
                        font=FONTS['small'],
                        borderwidth=1, relief='flat')
        style.map('Packets.Treeview',
                  background=[('selected', C['accent'])],
                  foreground=[('selected', '#ffffff')])
        style.map('Packets.Treeview.Heading',
                  background=[('active', C['hover'])])

        style.configure('Dark.Vertical.TScrollbar',
                        background=C['surface'],
                        troughcolor=C['panel'],
                        arrowcolor=C['muted'], borderwidth=0)
        style.configure('Dark.Horizontal.TScrollbar',
                        background=C['surface'],
                        troughcolor=C['panel'],
                        arrowcolor=C['muted'], borderwidth=0)

        # Combobox style fix for dark & light mode
        style.configure('Dark.TCombobox',
                        background=C['surface'],
                        foreground=C['text'],
                        fieldbackground=C['surface'],
                        arrowcolor=C['accent'],
                        bordercolor=C['border'],
                        lightcolor=C['border'],
                        darkcolor=C['border'])
        style.map('Dark.TCombobox',
                  fieldbackground=[('readonly', C['surface']), ('focus', C['surface'])],
                  selectbackground=[('readonly', C['surface']), ('focus', C['surface'])],
                  selectforeground=[('readonly', C['text']), ('focus', C['text'])],
                  foreground=[('readonly', C['text']), ('focus', C['text'])])

        style.configure('Dark.TNotebook',
                        background=C['bg'], borderwidth=0)
        style.configure('Dark.TNotebook.Tab',
                        background=C['surface'],
                        foreground=C['muted'],
                        font=FONTS['small'],
                        padding=[12, 6], borderwidth=0)
        style.map('Dark.TNotebook.Tab',
                  background=[('selected', C['panel'])],
                  foreground=[('selected', C['accent'])])

        style.configure('Dark.TSeparator', background=C['border'])

        # Option database for Combobox popups
        self.root.option_add('*TCombobox*Listbox.background', C['surface'])
        self.root.option_add('*TCombobox*Listbox.foreground', C['text'])
        self.root.option_add('*TCombobox*Listbox.selectBackground', C['accent'])
        self.root.option_add('*TCombobox*Listbox.selectForeground', '#ffffff')

    # ────────────────────────────────────────────────
    #   UI BUILDER
    # ────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._build_toolbar()
        self._sep1 = ttk.Separator(self.root, orient='horizontal', style='Dark.TSeparator')
        self._sep1.pack(fill=tk.X)
        self._build_main_area()
        self._build_statusbar()

    def _build_titlebar(self):
        C = self.C
        self._titlebar = tk.Frame(self.root, bg=C['panel'], height=54)
        self._titlebar.pack(fill=tk.X)
        self._titlebar.pack_propagate(False)

        left = tk.Frame(self._titlebar, bg=C['panel'])
        left.pack(side=tk.LEFT, padx=18, pady=8)

        self._lbl_logo = tk.Label(left, text="◈", font=('Consolas', 22, 'bold'), bg=C['panel'], fg=C['accent'])
        self._lbl_logo.pack(side=tk.LEFT)
        self._lbl_title = tk.Label(left, text="  NetScope", font=('Consolas', 18, 'bold'), bg=C['panel'], fg=C['text'])
        self._lbl_title.pack(side=tk.LEFT)
        self._lbl_sub = tk.Label(left, text="  v2.0  ·  IDS Enabled", font=('Consolas', 9), bg=C['panel'], fg=C['green'])
        self._lbl_sub.pack(side=tk.LEFT, pady=(6, 0))

        right = tk.Frame(self._titlebar, bg=C['panel'])
        right.pack(side=tk.RIGHT, padx=20)

        self._live_dot = tk.Label(right, text="●", font=('Consolas', 14), bg=C['panel'], fg=C['border'])
        self._live_dot.pack(side=tk.LEFT)

        self._pkt_counter = tk.Label(right, text="  0 packets", font=FONTS['heading'], bg=C['panel'], fg=C['muted'])
        self._pkt_counter.pack(side=tk.LEFT)

        self._bytes_label = tk.Label(right, text="   0 B", font=FONTS['small'], bg=C['panel'], fg=C['muted'])
        self._bytes_label.pack(side=tk.LEFT, padx=(5, 0))

    def _build_toolbar(self):
        C = self.C
        self._toolbar = tk.Frame(self.root, bg=C['bg'], height=56)
        self._toolbar.pack(fill=tk.X, padx=10, pady=6)
        self._toolbar.pack_propagate(False)

        # Interface
        self._lbl_iface = self._make_label(self._toolbar, "INTERFACE")
        self._lbl_iface.pack(side=tk.LEFT, padx=(5, 4))
        self._iface_var = tk.StringVar()
        iface_names = [i['display'] for i in self._interfaces]
        self._iface_cb = ttk.Combobox(
            self._toolbar, textvariable=self._iface_var,
            values=iface_names, width=32, state='readonly',
            style='Dark.TCombobox', font=FONTS['small'])
        self._iface_cb.pack(side=tk.LEFT, padx=(0, 15), ipady=4)
        if iface_names:
            self._iface_cb.current(0)

        # Filter
        self._lbl_filter = self._make_label(self._toolbar, "FILTER")
        self._lbl_filter.pack(side=tk.LEFT, padx=(0, 4))
        self._filter_var = tk.StringVar()
        self._filter_entry = tk.Entry(
            self._toolbar, textvariable=self._filter_var,
            width=28, font=FONTS['small'],
            bg=C['surface'], fg=C['text'],
            insertbackground=C['accent'],
            relief='flat', bd=0)
        self._filter_entry.pack(side=tk.LEFT, ipady=6, padx=(0, 4))

        self._filter_preset_var = tk.StringVar(value="Presets ▾")
        self._preset_cb = ttk.Combobox(
            self._toolbar, textvariable=self._filter_preset_var,
            values=list(BPF_FILTER_EXAMPLES.keys()),
            width=14, state='readonly',
            style='Dark.TCombobox', font=FONTS['small'])
        self._preset_cb.pack(side=tk.LEFT, padx=(0, 15), ipady=4)
        self._preset_cb.bind('<<ComboboxSelected>>', self._apply_filter_preset)

        # Buttons
        self._btn_start = self._make_btn(self._toolbar, "▶  START", C['green'], command=self._start_capture)
        self._btn_start.pack(side=tk.LEFT, padx=4, ipady=6, ipadx=6)

        self._btn_stop = self._make_btn(self._toolbar, "■  STOP", C['red'], command=self._stop_capture, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=4, ipady=6, ipadx=6)

        self._btn_clear = self._make_btn(self._toolbar, "↺  CLEAR", C['muted'], command=self._clear_capture)
        self._btn_clear.pack(side=tk.LEFT, padx=4, ipady=6, ipadx=6)

        self._btn_theme = self._make_btn(self._toolbar, "🌙  Dark", C['purple'], command=self._toggle_theme)
        self._btn_theme.pack(side=tk.RIGHT, padx=4, ipady=6, ipadx=6)

        self._btn_stats = self._make_btn(self._toolbar, "📊  Statistics", C['purple'], command=self._show_stats)
        self._btn_stats.pack(side=tk.RIGHT, padx=4, ipady=6, ipadx=6)

        self._btn_export = self._make_btn(self._toolbar, "💾  Export", C['orange'], command=self._show_export)
        self._btn_export.pack(side=tk.RIGHT, padx=4, ipady=6, ipadx=6)

    def _build_main_area(self):
        C = self.C
        self._container = tk.Frame(self.root, bg=C['bg'])
        self._container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 0))

        self._build_sidebar(self._container)

        self._center_frame = tk.Frame(self._container, bg=C['bg'])
        self._center_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self._build_packet_list(self._center_frame)
        self._build_detail_panel(self._center_frame)

    def _build_sidebar(self, parent):
        C = self.C
        self._sidebar = tk.Frame(parent, bg=C['panel'], width=210, relief='flat')
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self._sidebar.pack_propagate(False)

        self._s_lbl1 = tk.Label(self._sidebar, text="  LIVE STATS", font=FONTS['heading'], bg=C['panel'], fg=C['accent'], anchor='w')
        self._s_lbl1.pack(fill=tk.X, padx=10, pady=(14, 8))

        self._stat_labels = {}
        stats_config = [
            ('total', '⬡ Total', C['text']),
            ('tcp',   '◈ TCP',   C['accent']),
            ('udp',   '◈ UDP',   C['green']),
            ('icmp',  '◈ ICMP',  C['yellow']),
            ('arp',   '◈ ARP',   C['purple']),
            ('dns',   '◈ DNS',   C['cyan']),
            ('http',  '◈ HTTP',  C['orange']),
            ('https', '◈ HTTPS', C['green']),
            ('other', '◈ Other', C['muted']),
        ]

        for key, label, color in stats_config:
            row = tk.Frame(self._sidebar, bg=C['panel'])
            row.pack(fill=tk.X, padx=10, pady=2)
            tk.Label(row, text=label, font=FONTS['small'], bg=C['panel'], fg=C['muted'], width=10, anchor='w').pack(side=tk.LEFT)
            val_lbl = tk.Label(row, text="0", font=('Consolas', 9, 'bold'), bg=C['panel'], fg=color, anchor='e')
            val_lbl.pack(side=tk.RIGHT)
            self._stat_labels[key] = val_lbl

        self._s_lbl2 = tk.Label(self._sidebar, text="  ⚡ BANDWIDTH", font=FONTS['heading'], bg=C['panel'], fg=C['cyan'], anchor='w')
        self._s_lbl2.pack(fill=tk.X, padx=10, pady=(12, 4))

        bw_row = tk.Frame(self._sidebar, bg=C['panel'])
        bw_row.pack(fill=tk.X, padx=10, pady=2)
        tk.Label(bw_row, text="Speed:", font=FONTS['small'], bg=C['panel'], fg=C['muted']).pack(side=tk.LEFT)
        self._bw_speed = tk.Label(bw_row, text="0 B/s", font=('Consolas', 11, 'bold'), bg=C['panel'], fg=C['cyan'])
        self._bw_speed.pack(side=tk.RIGHT)

        bw_row2 = tk.Frame(self._sidebar, bg=C['panel'])
        bw_row2.pack(fill=tk.X, padx=10, pady=2)
        tk.Label(bw_row2, text="Peak:", font=FONTS['small'], bg=C['panel'], fg=C['muted']).pack(side=tk.LEFT)
        self._bw_peak = tk.Label(bw_row2, text="0 B/s", font=('Consolas', 9, 'bold'), bg=C['panel'], fg=C['yellow'])
        self._bw_peak.pack(side=tk.RIGHT)

        self._s_lbl3 = tk.Label(self._sidebar, text="  DATA CAPTURED", font=FONTS['small'], bg=C['panel'], fg=C['muted'], anchor='w')
        self._s_lbl3.pack(fill=tk.X, padx=10, pady=(10, 0))
        self._bytes_sidebar = tk.Label(self._sidebar, text="0 B", font=('Consolas', 13, 'bold'), bg=C['panel'], fg=C['accent'])
        self._bytes_sidebar.pack(fill=tk.X, padx=10, pady=(2, 8))

        self._s_lbl4 = tk.Label(self._sidebar, text="  🛡️ IDS ALERTS", font=FONTS['heading'], bg=C['panel'], fg=C['red'], anchor='w')
        self._s_lbl4.pack(fill=tk.X, padx=10, pady=(2, 4))

        ids_frame = tk.Frame(self._sidebar, bg=C['panel'])
        ids_frame.pack(fill=tk.X, padx=10)

        self._ids_critical = tk.Label(ids_frame, text="🔴 Critical: 0", font=('Consolas', 8, 'bold'), bg=C['panel'], fg='#ff4444', anchor='w')
        self._ids_critical.pack(fill=tk.X, pady=1)

        self._ids_warning = tk.Label(ids_frame, text="🟡 Warning: 0", font=('Consolas', 8, 'bold'), bg=C['panel'], fg='#ffaa00', anchor='w')
        self._ids_warning.pack(fill=tk.X, pady=1)

        self._s_lbl5 = tk.Label(self._sidebar, text="  TOP SOURCE IPs", font=FONTS['small'], bg=C['panel'], fg=C['muted'], anchor='w')
        self._s_lbl5.pack(fill=tk.X, padx=10, pady=(8, 4))

        self._top_ips_frame = tk.Frame(self._sidebar, bg=C['panel'])
        self._top_ips_frame.pack(fill=tk.X, padx=10)

        self._top_ip_labels = []
        for _ in range(5):
            lbl = tk.Label(self._top_ips_frame, text="", font=('Consolas', 7), bg=C['panel'], fg=C['muted'], anchor='w')
            lbl.pack(fill=tk.X, pady=1)
            self._top_ip_labels.append(lbl)

    def _build_packet_list(self, parent):
        C = self.C
        self._pkt_header = tk.Frame(parent, bg=C['bg'])
        self._pkt_header.pack(fill=tk.X, pady=(0, 4))

        self._lbl_cap_packets = tk.Label(self._pkt_header, text="CAPTURED PACKETS", font=FONTS['heading'], bg=C['bg'], fg=C['accent'])
        self._lbl_cap_packets.pack(side=tk.LEFT)

        self._search_var = tk.StringVar()
        self._search_var.trace_add('write', self._on_search)

        self._search_frame = tk.Frame(self._pkt_header, bg=C['surface'])
        self._search_frame.pack(side=tk.RIGHT)
        self._search_icon = tk.Label(self._search_frame, text=" 🔍 ", font=FONTS['small'], bg=C['surface'], fg=C['muted'])
        self._search_icon.pack(side=tk.LEFT)
        self._search_entry = tk.Entry(
            self._search_frame, textvariable=self._search_var,
            font=FONTS['small'], bg=C['surface'], fg=C['text'],
            insertbackground=C['accent'], relief='flat', width=20)
        self._search_entry.pack(side=tk.LEFT, ipady=4)

        self._tree_frame = tk.Frame(parent, bg=C['border'])
        self._tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ('no', 'time', 'source', 'destination', 'protocol', 'length', 'info')
        self._tree = ttk.Treeview(
            self._tree_frame, columns=cols,
            show='headings', style='Packets.Treeview', selectmode='browse')

        col_config = [
            ('no', 'No.', 60, tk.CENTER),
            ('time', 'Time', 110, tk.W),
            ('source', 'Source', 145, tk.W),
            ('destination', 'Destination', 145, tk.W),
            ('protocol', 'Protocol', 90, tk.CENTER),
            ('length', 'Length', 70, tk.CENTER),
            ('info', 'Info', 600, tk.W),
        ]
        for col_id, heading, width, anchor in col_config:
            self._tree.heading(col_id, text=heading)
            self._tree.column(col_id, width=width, anchor=anchor, minwidth=40)

        v_scroll = ttk.Scrollbar(self._tree_frame, orient='vertical', command=self._tree.yview, style='Dark.Vertical.TScrollbar')
        h_scroll = ttk.Scrollbar(self._tree_frame, orient='horizontal', command=self._tree.xview, style='Dark.Horizontal.TScrollbar')
        self._tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self._tree.pack(fill=tk.BOTH, expand=True)

        self._apply_tree_tags()

        self._tree.bind('<<TreeviewSelect>>', self._on_packet_select)
        self._tree.bind('<Double-1>', self._on_packet_double_click)

        self._context_menu = tk.Menu(
            self._tree, tearoff=0, font=FONTS['small'],
            bg=C['panel'], fg=C['text'],
            activebackground=C['accent'], activeforeground='#ffffff')
        self._context_menu.add_command(label="🌍  Lookup Source IP Location", command=self._geoip_lookup_source)
        self._context_menu.add_command(label="🌍  Lookup Dest IP Location", command=self._geoip_lookup_dest)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="📋  Copy Source IP", command=self._copy_source_ip)
        self._context_menu.add_command(label="📋  Copy Dest IP", command=self._copy_dest_ip)

        self._tree.bind('<Button-3>', self._show_context_menu)

    def _apply_tree_tags(self):
        tags_dict = PROTOCOL_TAG_COLORS_DARK if self._current_theme == 'dark' else PROTOCOL_TAG_COLORS_LIGHT
        for proto, colors in tags_dict.items():
            self._tree.tag_configure(proto, background=colors['bg'], foreground=colors['fg'])

    def _build_detail_panel(self, parent):
        C = self.C
        self._notebook = ttk.Notebook(parent, style='Dark.TNotebook')
        self._notebook.pack(fill=tk.BOTH, expand=False, pady=(8, 0))
        self._notebook.configure(height=220)

        # Tab 1: Packet Details
        self._detail_tab = tk.Frame(self._notebook, bg=C['panel'])
        self._notebook.add(self._detail_tab, text="  📋 Packet Details  ")
        self._detail_text = scrolledtext.ScrolledText(
            self._detail_tab, font=('Consolas', 9),
            bg=C['panel'], fg=C['detail_fg'],
            insertbackground=C['accent'], relief='flat', bd=0, wrap=tk.WORD, state='disabled')
        self._detail_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Tab 2: Hex View
        self._hex_tab = tk.Frame(self._notebook, bg=C['panel'])
        self._notebook.add(self._hex_tab, text="  ⬡ Hex View  ")
        self._hex_text = scrolledtext.ScrolledText(
            self._hex_tab, font=('Consolas', 9),
            bg=C['panel'], fg=C['hex_fg'],
            insertbackground=C['accent'], relief='flat', bd=0, wrap=tk.NONE, state='disabled')
        self._hex_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Tab 3: IDS Alerts
        self._alert_text = create_alert_tab(self._notebook, dark_bg=C['panel'], text_color=C['text'])

        # Tab 4: Notes
        self._notes_tab = tk.Frame(self._notebook, bg=C['panel'])
        self._notebook.add(self._notes_tab, text="  📝 Notes  ")
        self._lbl_notes = tk.Label(self._notes_tab, text="  Personal notes:", font=FONTS['small'], bg=C['panel'], fg=C['muted'], anchor='w')
        self._lbl_notes.pack(fill=tk.X, pady=(6, 2))
        self._notes_text = scrolledtext.ScrolledText(
            self._notes_tab, font=('Consolas', 9),
            bg=C['surface'], fg=C['text'],
            insertbackground=C['accent'], relief='flat', bd=0)
        self._notes_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    def _build_statusbar(self):
        C = self.C
        self._statusbar = tk.Frame(self.root, bg=C['panel'], height=28)
        self._statusbar.pack(fill=tk.X, side=tk.BOTTOM)
        self._statusbar.pack_propagate(False)

        self._status_var = tk.StringVar(value="  ◉  Ready  ·  IDS Active  ·  Select interface and click START")
        self._status_lbl = tk.Label(
            self._statusbar, textvariable=self._status_var,
            font=FONTS['small'], bg=C['panel'], fg=C['muted'], anchor='w')
        self._status_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        self._ids_status = tk.Label(self._statusbar, text="🛡️ IDS: Active  ", font=FONTS['small'], bg=C['panel'], fg=C['green'])
        self._ids_status.pack(side=tk.RIGHT)

        self._ver_label = tk.Label(self._statusbar, text="NetScope v2.0  ", font=FONTS['small'], bg=C['panel'], fg=C['border'])
        self._ver_label.pack(side=tk.RIGHT)

    # ────────────────────────────────────────────────
    #   WIDGET FACTORIES
    # ────────────────────────────────────────────────

    def _make_label(self, parent, text):
        return tk.Label(parent, text=text, font=('Consolas', 8, 'bold'), bg=self.C['bg'], fg=self.C['muted'])

    def _make_btn(self, parent, text, color, command=None, state=tk.NORMAL):
        btn = tk.Button(
            parent, text=text, font=FONTS['small'],
            bg=self.C['surface'], fg=color,
            activebackground=color, activeforeground='#ffffff',
            relief='flat', bd=0, cursor='hand2',
            command=command, state=state)

        # Hover bindings using dynamic active theme color
        btn.bind('<Enter>', lambda e, b=btn, c=color: b.configure(bg=c, fg='#ffffff') if b['state'] != 'disabled' else None)
        btn.bind('<Leave>', lambda e, b=btn, c=color: b.configure(bg=self.C['surface'], fg=c) if b['state'] != 'disabled' else None)
        self._buttons.append((btn, color))
        return btn

    # ────────────────────────────────────────────────
    #   CAPTURE CONTROLS
    # ────────────────────────────────────────────────

    def _start_capture(self):
        if self.is_capturing:
            return
        idx = self._iface_cb.current()
        iface = (self._interfaces[idx]['name'] if 0 <= idx < len(self._interfaces) else None)
        bpf = self._filter_var.get().strip()

        self.is_capturing = True
        self._btn_start.configure(state=tk.DISABLED)
        self._btn_stop.configure(state=tk.NORMAL)
        self._iface_cb.configure(state='disabled')
        self._set_status(f"▶  Capturing on {iface or 'default'}  {'· Filter: ' + bpf if bpf else '· No filter'}  ·  IDS Active", self.C['green'])
        self._live_dot.configure(fg=self.C['cyan'])

        ok, msg = self.sniffer.start(interface=iface, bpf_filter=bpf, packet_cb=self._on_packet_received)
        if not ok:
            self.is_capturing = False
            self._btn_start.configure(state=tk.NORMAL)
            self._btn_stop.configure(state=tk.DISABLED)
            self._iface_cb.configure(state='readonly')
            self._live_dot.configure(fg=self.C['border'])
            messagebox.showerror("Capture Error", f"Failed:\n{msg}\n\nRun as Administrator!")

    def _stop_capture(self):
        if not self.is_capturing:
            return
        self.is_capturing = False
        self.sniffer.stop()
        self._btn_start.configure(state=tk.NORMAL)
        self._btn_stop.configure(state=tk.DISABLED)
        self._iface_cb.configure(state='readonly')
        self._live_dot.configure(fg=self.C['border'])
        total = self.sniffer.stats['total_packets']
        alerts = len(self.sniffer.ids.alerts)
        self._set_status(f"■  Stopped  ·  {total} packets  ·  {alerts} IDS alerts", self.C['yellow'])

    def _clear_capture(self):
        if self.is_capturing:
            self._stop_capture()
        self._tree.delete(*self._tree.get_children())
        self._all_packets_shown.clear()
        self._selected_index = None
        self.sniffer.captured_packets.clear()
        self.sniffer._reset_stats()
        self._set_detail_text("Select a packet to view details.")
        self._set_hex_text("")
        self._pkt_counter.configure(text="  0 packets")
        self._bytes_label.configure(text="   0 B")
        self._bytes_sidebar.configure(text="0 B")
        for lbl in self._stat_labels.values():
            lbl.configure(text="0")
        for lbl in self._top_ip_labels:
            lbl.configure(text="")
        self._bw_speed.configure(text="0 B/s")
        self._bw_peak.configure(text="0 B/s")
        self._ids_critical.configure(text="🔴 Critical: 0")
        self._ids_warning.configure(text="🟡 Warning: 0")
        self._set_status("↺  Cleared  ·  Ready", self.C['muted'])

    # ────────────────────────────────────────────────
    #   PACKET CALLBACK
    # ────────────────────────────────────────────────

    def _on_packet_received(self, packet_info):
        self.root.after(0, self._add_packet_row, packet_info)

    def _add_packet_row(self, pkt):
        proto = pkt['protocol']
        tags_dict = PROTOCOL_TAG_COLORS_DARK if self._current_theme == 'dark' else PROTOCOL_TAG_COLORS_LIGHT
        tag = (proto if proto in tags_dict else 'OTHER')
        item = self._tree.insert(
            '', tk.END,
            values=(
                pkt['number'], pkt['timestamp'],
                pkt['source'], pkt['destination'],
                pkt['protocol'],
                f"{pkt['length']} B", pkt['info']),
            tags=(tag,))
        self._all_packets_shown.append(item)
        if len(self._all_packets_shown) % 5 == 0:
            self._tree.see(item)
        total = self.sniffer.stats['total_packets']
        if total % 10 == 0 or total < 20:
            self._update_counters()

    # ────────────────────────────────────────────────
    #   IDS ALERT CALLBACK
    # ────────────────────────────────────────────────

    def _on_ids_alert(self, alert):
        self.root.after(0, self._display_alert, alert)

    def _display_alert(self, alert):
        add_alert_to_text(self._alert_text, alert)
        show_alert_popup(self.root, alert, theme=self._current_theme)
        if alert.get('severity') == 'CRITICAL':
            self._notebook.select(self._alert_text.master)

    # ────────────────────────────────────────────────
    #   LIVE UPDATE TIMER
    # ────────────────────────────────────────────────

    def _start_live_update(self):
        self._update_counters()
        self.root.after(1000, self._start_live_update)

    def _update_counters(self):
        s = self.sniffer.stats
        total = s['total_packets']
        total_bytes = s['total_bytes']

        self._pkt_counter.configure(
            text=f"  {total:,} packets",
            fg=(self.C['accent'] if total > 0 else self.C['muted']))
        self._bytes_label.configure(
            text=f"   {format_bytes(total_bytes)}",
            fg=(self.C['green'] if total_bytes > 0 else self.C['muted']))
        self._bytes_sidebar.configure(text=format_bytes(total_bytes))

        for key, val in [
            ('total', total),
            ('tcp', s['tcp_count']),
            ('udp', s['udp_count']),
            ('icmp', s['icmp_count']),
            ('arp', s['arp_count']),
            ('dns', s['dns_count']),
            ('http', s['http_count']),
            ('https', s['https_count']),
            ('other', s['other_count'])
        ]:
            if key in self._stat_labels:
                self._stat_labels[key].configure(text=f"{val:,}")

        self._bw_speed.configure(text=self.sniffer.bandwidth.get_speed_formatted())
        self._bw_peak.configure(text=self.sniffer.bandwidth.get_peak_formatted())

        ids_summary = self.sniffer.ids.get_alert_summary()
        self._ids_critical.configure(text=f"🔴 Critical: {ids_summary['CRITICAL']}")
        self._ids_warning.configure(text=f"🟡 Warning: {ids_summary['WARNING']}")

        top = sorted(s['ip_sources'].items(), key=lambda x: x[1], reverse=True)[:5]
        for i, lbl in enumerate(self._top_ip_labels):
            if i < len(top):
                ip, count = top[i]
                short = (ip[-16:] if len(ip) > 16 else ip)
                lbl.configure(text=f"{short}  ({count})", fg=self.C['accent'])
            else:
                lbl.configure(text="")

    # ────────────────────────────────────────────────
    #   PACKET SELECTION
    # ────────────────────────────────────────────────

    def _on_packet_select(self, event):
        selected = self._tree.selection()
        if not selected:
            return
        item = self._tree.item(selected[0])
        pkt_no = int(item['values'][0]) - 1
        self._selected_index = pkt_no
        self._set_detail_text(self.sniffer.get_packet_details(pkt_no))
        self._load_hex_view(pkt_no)

    def _on_packet_double_click(self, event):
        if self._selected_index is not None:
            self._open_packet_window(self._selected_index)

    def _open_packet_window(self, index):
        details = self.sniffer.get_packet_details(index)
        win = tk.Toplevel(self.root)
        win.title(f"Packet #{index + 1}")
        win.geometry("800x600")
        win.configure(bg=self.C['bg'])
        pkt = self.sniffer.captured_packets[index]
        tk.Label(
            win,
            text=f"  Packet #{pkt['number']}  ·  {pkt['protocol']}  ·  {pkt['source']} → {pkt['destination']}",
            font=FONTS['heading'], bg=self.C['panel'], fg=self.C['accent'], anchor='w').pack(fill=tk.X)
        text = scrolledtext.ScrolledText(
            win, font=('Consolas', 10),
            bg=self.C['panel'], fg=self.C['detail_fg'], relief='flat', bd=0)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        text.insert('1.0', details)
        text.configure(state='disabled')
        tk.Button(
            win, text="Close", font=FONTS['small'],
            bg=self.C['surface'], fg=self.C['red'], relief='flat', command=win.destroy,
            padx=20, pady=6).pack(pady=(0, 10))

    def _set_detail_text(self, text):
        self._detail_text.configure(state='normal')
        self._detail_text.delete('1.0', tk.END)
        self._detail_text.insert('1.0', text)
        self._detail_text.configure(state='disabled')

    def _load_hex_view(self, index):
        try:
            pkt = self.sniffer.captured_packets[index]
            raw = bytes(pkt['raw_packet'])
            lines = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i + 16]
                h = ' '.join(f'{b:02x}' for b in chunk)
                a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f"  {i:04x}   {h:<48}   {a}")
            self._set_hex_text('\n'.join(lines))
        except Exception:
            pass

    def _set_hex_text(self, text):
        self._hex_text.configure(state='normal')
        self._hex_text.delete('1.0', tk.END)
        self._hex_text.insert('1.0', text)
        self._hex_text.configure(state='disabled')

    # ────────────────────────────────────────────────
    #   SEARCH / FILTER
    # ────────────────────────────────────────────────

    def _on_search(self, *args):
        query = self._search_var.get().lower()
        if not query:
            for item in self._all_packets_shown:
                try:
                    self._tree.reattach(item, '', tk.END)
                except Exception:
                    pass
            return
        for item in self._all_packets_shown:
            try:
                vals = [str(v).lower() for v in self._tree.item(item)['values']]
                if any(query in v for v in vals):
                    self._tree.reattach(item, '', tk.END)
                else:
                    self._tree.detach(item)
            except Exception:
                pass

    def _apply_filter_preset(self, event):
        selected = self._filter_preset_var.get()
        if selected in BPF_FILTER_EXAMPLES:
            self._filter_var.set(BPF_FILTER_EXAMPLES[selected])
        self._filter_preset_var.set("Presets ▾")

    # ────────────────────────────────────────────────
    #   GEOIP CONTEXT MENU
    # ────────────────────────────────────────────────

    def _show_context_menu(self, event):
        item = self._tree.identify_row(event.y)
        if item:
            self._tree.selection_set(item)
            self._context_menu.post(event.x_root, event.y_root)

    def _geoip_lookup_source(self):
        selected = self._tree.selection()
        if selected:
            ip = self._tree.item(selected[0])['values'][2]
            if ip and ip != 'N/A':
                show_geoip_window(self.root, str(ip), theme=self._current_theme)

    def _geoip_lookup_dest(self):
        selected = self._tree.selection()
        if selected:
            ip = self._tree.item(selected[0])['values'][3]
            if ip and ip != 'N/A':
                show_geoip_window(self.root, str(ip), theme=self._current_theme)

    def _copy_source_ip(self):
        selected = self._tree.selection()
        if selected:
            ip = str(self._tree.item(selected[0])['values'][2])
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def _copy_dest_ip(self):
        selected = self._tree.selection()
        if selected:
            ip = str(self._tree.item(selected[0])['values'][3])
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    # ────────────────────────────────────────────────
    #   THEME TOGGLE
    # ────────────────────────────────────────────────

    def _toggle_theme(self):
        if self._current_theme == 'dark':
            self._current_theme = 'light'
            self.C = THEMES['light']
            self._btn_theme.configure(text="☀️  Light", fg=self.C['yellow'])
        else:
            self._current_theme = 'dark'
            self.C = THEMES['dark']
            self._btn_theme.configure(text="🌙  Dark", fg=self.C['purple'])

        # Re-apply styles and recolor all elements
        self._build_styles()
        self._apply_tree_tags()
        self._recolor_ui()

        self._set_status(f"🎨  Theme: {self._current_theme.title()} mode", self.C['accent'])

    def _recolor_ui(self):
        C = self.C

        # Root & Main Containers
        self.root.configure(bg=C['bg'])
        self._container.configure(bg=C['bg'])
        self._center_frame.configure(bg=C['bg'])

        # Titlebar
        self._titlebar.configure(bg=C['panel'])
        for w in self._titlebar.winfo_children():
            w.configure(bg=C['panel'])
            for child in w.winfo_children():
                if child not in (self._lbl_sub, self._live_dot, self._pkt_counter, self._bytes_label):
                    child.configure(bg=C['panel'], fg=C['text'] if isinstance(child, tk.Label) else None)
        self._lbl_logo.configure(fg=C['accent'])
        self._lbl_title.configure(fg=C['text'])

        # Toolbar
        self._toolbar.configure(bg=C['bg'])
        self._lbl_iface.configure(bg=C['bg'], fg=C['muted'])
        self._lbl_filter.configure(bg=C['bg'], fg=C['muted'])
        self._filter_entry.configure(bg=C['surface'], fg=C['text'], insertbackground=C['accent'])

        # Custom Buttons
        for btn, color in self._buttons:
            btn.configure(bg=C['surface'])

        # Sidebar
        self._sidebar.configure(bg=C['panel'])
        for w in self._sidebar.winfo_children():
            if isinstance(w, tk.Label):
                w.configure(bg=C['panel'])
            elif isinstance(w, tk.Frame):
                w.configure(bg=C['panel'])
                for child in w.winfo_children():
                    if isinstance(child, tk.Label):
                        child.configure(bg=C['panel'])

        self._s_lbl1.configure(fg=C['accent'])
        self._s_lbl2.configure(fg=C['cyan'])
        self._s_lbl3.configure(fg=C['muted'])
        self._s_lbl4.configure(fg=C['red'])
        self._s_lbl5.configure(fg=C['muted'])

        # Packet Header & Search
        self._pkt_header.configure(bg=C['bg'])
        self._lbl_cap_packets.configure(bg=C['bg'], fg=C['accent'])
        self._search_frame.configure(bg=C['surface'])
        self._search_icon.configure(bg=C['surface'], fg=C['muted'])
        self._search_entry.configure(bg=C['surface'], fg=C['text'], insertbackground=C['accent'])

        # Context Menu
        self._context_menu.configure(bg=C['panel'], fg=C['text'], activebackground=C['accent'])

        # Notebook Tabs
        self._detail_tab.configure(bg=C['panel'])
        self._hex_tab.configure(bg=C['panel'])
        self._notes_tab.configure(bg=C['panel'])
        self._lbl_notes.configure(bg=C['panel'], fg=C['muted'])

        self._detail_text.configure(bg=C['panel'], fg=C['detail_fg'], insertbackground=C['accent'])
        self._hex_text.configure(bg=C['panel'], fg=C['hex_fg'], insertbackground=C['accent'])
        self._notes_text.configure(bg=C['surface'], fg=C['text'], insertbackground=C['accent'])
        self._alert_text.configure(bg=C['panel'], fg=C['text'], insertbackground=C['accent'])

        # Statusbar
        self._statusbar.configure(bg=C['panel'])
        self._status_lbl.configure(bg=C['panel'], fg=C['muted'])
        self._ids_status.configure(bg=C['panel'], fg=C['green'])
        self._ver_label.configure(bg=C['panel'], fg=C['border'])

    # ────────────────────────────────────────────────
    #   STATISTICS
    # ────────────────────────────────────────────────

    def _show_stats(self):
        if self.sniffer.stats['total_packets'] == 0:
            messagebox.showinfo("No Data", "Start a capture first!")
            return
        s = self.sniffer.stats
        stats_for_chart = {
            'total_packets': s['total_packets'],
            'total_bytes_fmt': format_bytes(s['total_bytes']),
            'tcp_count': s['tcp_count'],
            'udp_count': s['udp_count'],
            'icmp_count': s['icmp_count'],
            'arp_count': s['arp_count'],
            'dns_count': s['dns_count'],
            'http_count': s['http_count'],
            'https_count': s['https_count'],
            'other_count': s['other_count'],
            'ip_sources': dict(s['ip_sources']),
            'ip_destinations': dict(s['ip_destinations']),
            'packet_sizes': s['packet_sizes'].copy(),
            'pps_data': dict(s['pps_data']),
        }
        show_statistics_window(self.root, stats_for_chart, self.sniffer.captured_packets, theme=self._current_theme)

    # ────────────────────────────────────────────────
    #   EXPORT
    # ────────────────────────────────────────────────

    def _show_export(self):
        if self.sniffer.stats['total_packets'] == 0:
            messagebox.showinfo("No Data", "Nothing to export!")
            return

        export_win = tk.Toplevel(self.root)
        export_win.title("Export Capture Data")
        export_win.geometry("380x280")
        export_win.configure(bg=self.C['panel'])
        export_win.resizable(False, False)
        export_win.grab_set()

        export_win.update_idletasks()
        x = (self.root.winfo_x() + (self.root.winfo_width() - 380) // 2)
        y = (self.root.winfo_y() + (self.root.winfo_height() - 280) // 2)
        export_win.geometry(f"380x280+{x}+{y}")

        tk.Label(export_win, text="💾  EXPORT CAPTURE", font=FONTS['heading'], bg=self.C['panel'], fg=self.C['accent']).pack(pady=(20, 5))
        tk.Label(export_win, text=f"  {self.sniffer.stats['total_packets']} packets  ·  {format_bytes(self.sniffer.stats['total_bytes'])}",
                 font=FONTS['small'], bg=self.C['panel'], fg=self.C['muted']).pack(pady=(0, 20))

        ttk.Separator(export_win, orient='horizontal').pack(fill=tk.X, padx=20, pady=(0, 20))

        def export_txt():
            fp = filedialog.asksaveasfilename(
                defaultextension=".txt", initialfile=f"netscope_{get_date_filename()}.txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")], parent=export_win)
            if fp:
                ok, result = self.sniffer.export_txt(fp)
                if ok:
                    messagebox.showinfo("Success", f"Exported!\n{result}", parent=export_win)
                    export_win.destroy()
                else:
                    messagebox.showerror("Error", f"Failed:\n{result}", parent=export_win)

        def export_pcap():
            fp = filedialog.asksaveasfilename(
                defaultextension=".pcap", initialfile=f"netscope_{get_date_filename()}.pcap",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")], parent=export_win)
            if fp:
                ok, result = self.sniffer.export_pcap(fp)
                if ok:
                    messagebox.showinfo("Success", f"Saved!\n{result}\n\nOpen with Wireshark.", parent=export_win)
                    export_win.destroy()
                else:
                    messagebox.showerror("Error", f"Failed:\n{result}", parent=export_win)

        btn_frame = tk.Frame(export_win, bg=self.C['panel'])
        btn_frame.pack()

        for text, color, cmd in [
            ("📄  Export as Text (.txt)", self.C['accent'], export_txt),
            ("📦  Export as PCAP (.pcap)", self.C['green'], export_pcap),
            ("✕  Cancel", self.C['red'], export_win.destroy),
        ]:
            btn = tk.Button(
                btn_frame, text=text, font=FONTS['small'],
                bg=self.C['surface'], fg=color,
                activebackground=color, activeforeground='#ffffff',
                relief='flat', bd=0, width=30, pady=8, command=cmd)
            btn.pack(pady=5)

    # ────────────────────────────────────────────────
    #   UTILITY
    # ────────────────────────────────────────────────

    def _set_status(self, msg, color=None):
        self._status_var.set(f"  {msg}")
        if color:
            self._status_lbl.configure(fg=color)

    def _on_close(self):
        if self.is_capturing:
            self.sniffer.stop()
        self.root.destroy()


# ══════════════════════════════════════════════════════════
#   ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    if sys.platform == 'win32':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("=" * 60)
            print("  ⚠  WARNING: Not running as Administrator!")
            print("  Right-click VS Code → Run as Administrator")
            print("=" * 60)

    root = tk.Tk()
    app = NetScopeApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()