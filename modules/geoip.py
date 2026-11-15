# GeoIP Lookup
"""
NetScope GeoIP Lookup
Resolves IP addresses to geographic locations using ip-api.com
"""

import urllib.request
import json
import tkinter as tk
from tkinter import ttk
import threading


def lookup_ip(ip_address, callback=None):
    """
    Lookup geographic info for an IP address.
    Uses free ip-api.com (no key needed, 45 req/min).
    Calls callback(result_dict) when done.
    """
    def _fetch():
        try:
            if ip_address in ('N/A', '0.0.0.0', '255.255.255.255', ''):
                result = {'status': 'fail', 'message': 'Invalid IP'}
            elif ip_address.startswith(('192.168.', '10.', '172.16.',
                                        '172.17.', '172.18.', '127.')):
                result = {
                    'status': 'success',
                    'query': ip_address,
                    'country': 'Private Network',
                    'city': 'Local',
                    'regionName': 'LAN',
                    'isp': 'Private',
                    'org': 'Local Network',
                    'lat': 0, 'lon': 0,
                    'timezone': 'Local',
                }
            else:
                url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,isp,org,lat,lon,timezone,query"
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'NetScope/1.0'
                })
                with urllib.request.urlopen(req, timeout=5) as resp:
                    result = json.loads(resp.read().decode())

            if callback:
                callback(result)

        except Exception as e:
            if callback:
                callback({'status': 'fail', 'message': str(e)})

    threading.Thread(target=_fetch, daemon=True).start()


def show_geoip_window(parent, ip_address, dark_bg='#0d1117'):
    """Show a GeoIP lookup window for the given IP"""
    win = tk.Toplevel(parent)
    win.title(f"🌍 GeoIP Lookup — {ip_address}")
    win.geometry("420x320")
    win.configure(bg=dark_bg)
    win.resizable(False, False)
    win.grab_set()

    # Center
    win.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() - 420) // 2
    y = parent.winfo_y() + (parent.winfo_height() - 320) // 2
    win.geometry(f"420x320+{x}+{y}")

    # Title
    tk.Label(win, text=f"🌍  GeoIP Lookup",
             font=('Consolas', 14, 'bold'),
             bg=dark_bg, fg='#58a6ff').pack(pady=(15, 2))

    tk.Label(win, text=f"IP: {ip_address}",
             font=('Consolas', 11),
             bg=dark_bg, fg='#c9d1d9').pack(pady=(0, 10))

    # Loading label
    loading = tk.Label(win, text="⏳  Looking up location...",
                       font=('Consolas', 10),
                       bg=dark_bg, fg='#8b949e')
    loading.pack(pady=20)

    # Result frame (hidden initially)
    result_frame = tk.Frame(win, bg='#161b22', relief='flat')

    def on_result(data):
        loading.pack_forget()

        if data.get('status') == 'success':
            result_frame.pack(fill=tk.BOTH, expand=True,
                              padx=20, pady=10)

            fields = [
                ("Country",  data.get('country', 'N/A')),
                ("Region",   data.get('regionName', 'N/A')),
                ("City",     data.get('city', 'N/A')),
                ("ISP",      data.get('isp', 'N/A')),
                ("Org",      data.get('org', 'N/A')),
                ("Timezone", data.get('timezone', 'N/A')),
                ("Coords",
                 f"{data.get('lat', '?')}, {data.get('lon', '?')}"),
            ]

            for label, value in fields:
                row = tk.Frame(result_frame, bg='#161b22')
                row.pack(fill=tk.X, pady=2, padx=10)

                tk.Label(row, text=f"{label}:",
                         font=('Consolas', 9, 'bold'),
                         bg='#161b22', fg='#8b949e',
                         width=10, anchor='w').pack(side=tk.LEFT)

                tk.Label(row, text=value,
                         font=('Consolas', 9),
                         bg='#161b22', fg='#c9d1d9',
                         anchor='w').pack(side=tk.LEFT, fill=tk.X)

            # Map link
            lat = data.get('lat', 0)
            lon = data.get('lon', 0)
            if lat and lon:
                map_url = f"https://maps.google.com/?q={lat},{lon}"
                tk.Label(win, text=f"📍 Open in Maps: {map_url}",
                         font=('Consolas', 8),
                         bg=dark_bg, fg='#58a6ff',
                         cursor='hand2').pack(pady=(0, 5))
        else:
            tk.Label(win,
                     text=f"❌  Lookup failed: "
                          f"{data.get('message', 'Unknown error')}",
                     font=('Consolas', 10),
                     bg=dark_bg, fg='#f85149').pack(pady=20)

    lookup_ip(ip_address, callback=on_result)

    # Close button
    tk.Button(win, text="Close",
              font=('Consolas', 9),
              bg='#21262d', fg='#c9d1d9',
              relief='flat', padx=20, pady=6,
              command=win.destroy).pack(side=tk.BOTTOM, pady=10)