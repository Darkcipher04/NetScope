# modules/alerts.py — NetScope v2.0 Alert System

import tkinter as tk
from tkinter import scrolledtext
import time

_last_alert_time: dict = {}
COOLDOWN_SECONDS = 30


def create_alert_tab(notebook, dark_bg="#161b22",
                     text_color="#c9d1d9"):
    """
    Create the IDS Alerts tab inside the given notebook and
    return the Text widget inside it.  Signature matches main.py.
    """
    tab = tk.Frame(notebook, bg=dark_bg)
    notebook.add(tab, text="  🛡️ IDS Alerts  ")

    alert_text = scrolledtext.ScrolledText(
        tab, wrap=tk.WORD,
        bg=dark_bg, fg=text_color,
        font=("Consolas", 9), relief=tk.FLAT,
        insertbackground=text_color,
        selectbackground="#1f6feb",
        highlightthickness=0, state=tk.DISABLED)
    alert_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

    alert_text.tag_configure("CRITICAL",
                              foreground="#ff4444",
                              font=("Consolas", 9, "bold"))
    alert_text.tag_configure("WARNING",
                              foreground="#ffaa00",
                              font=("Consolas", 9, "bold"))
    alert_text.tag_configure("INFO",
                              foreground="#58a6ff")
    alert_text.tag_configure("timestamp",
                              foreground="#8b949e")
    return alert_text


def add_alert_to_text(alert_text, alert: dict):
    """Append an alert to the alerts tab."""
    severity = alert.get("severity", "INFO")
    atype    = alert.get("type", "Unknown")
    message  = alert.get("message", "")
    source   = alert.get("source", "")
    ts = time.strftime("%H:%M:%S")

    try:
        alert_text.configure(state=tk.NORMAL)
        alert_text.insert(tk.END, f"[{ts}] ", "timestamp")
        alert_text.insert(tk.END, f"[{severity}] ", severity)
        alert_text.insert(tk.END, atype)
        if source:
            alert_text.insert(tk.END, f" from {source}")
        alert_text.insert(tk.END, f"\n    {message}\n\n")
        alert_text.see(tk.END)
        alert_text.configure(state=tk.DISABLED)
    except Exception:
        pass


def show_alert_popup(parent, alert: dict, theme="dark"):
    """Popup for CRITICAL alerts (with 30-sec cooldown)."""
    atype = alert.get("type", "Unknown")
    sev   = alert.get("severity", "INFO")
    if sev != "CRITICAL":
        return
    now = time.time()
    if atype in _last_alert_time and \
       now - _last_alert_time[atype] < COOLDOWN_SECONDS:
        return
    _last_alert_time[atype] = now

    popup = tk.Toplevel(parent)
    popup.title(f"⚠ NetScope Alert — {sev}")
    popup.geometry("420x180")
    popup.attributes("-topmost", True)
    popup.resizable(False, False)

    if theme == "light":
        bg, fg, accent, btn_bg = "#ffffff", "#1f2328", "#cf222e", "#f3f4f6"
    else:
        bg, fg, accent, btn_bg = "#1c1c2e", "#e0e0e0", "#ff4444", "#2a2a3e"

    popup.configure(bg=bg)
    tk.Label(popup, text=f"⚠  {sev} ALERT",
             bg=bg, fg=accent,
             font=("Segoe UI", 14, "bold")).pack(pady=(15, 5))

    detail = atype
    src = alert.get("source", "")
    if src:
        detail += f" from {src}"
    detail += f"\n{alert.get('message','')}"
    tk.Label(popup, text=detail, bg=bg, fg=fg,
             font=("Segoe UI", 10), justify=tk.LEFT,
             wraplength=380).pack(pady=5)

    tk.Button(popup, text="OK", command=popup.destroy,
              bg=btn_bg, fg=fg, font=("Segoe UI", 10),
              relief=tk.FLAT, padx=20, pady=4).pack(pady=10)

    popup.after(8000,
                lambda: popup.destroy()
                if popup.winfo_exists() else None)