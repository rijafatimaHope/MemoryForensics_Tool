"""
app.py  —  Role 4: GUI Architect
Memory Forensics Tool  |  CustomTkinter frontend

Schema driven by dummy_data.py:
  processes  : pid, name, ppid, time
  connections: pid, local_ip, local_port, remote_ip, remote_port, protocol
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import sys
import os

try:
    from integration import prepare_data_for_gui, search_in_prepared_data
    from dummy_data import sample_processes, sample_connections
    _INTEGRATION_AVAILABLE = True
except ImportError:
    _INTEGRATION_AVAILABLE = False
    # Fallback inline data so GUI can be developed and tested alone
    sample_processes = [
        {"pid": 1,    "name": "init",      "ppid": 0,    "time": "10:00:01"},
        {"pid": 2,    "name": "kthreadd",  "ppid": 0,    "time": "10:00:01"},
        {"pid": 1234, "name": "bash",      "ppid": 1,    "time": "10:05:32"},
        {"pid": 5678, "name": "malware",   "ppid": 1234, "time": "10:10:15"},
    ]
    sample_connections = [
        {"pid": 5678, "local_ip": "192.168.1.5", "local_port": 4444,
         "remote_ip": "185.130.5.253", "remote_port": 80,  "protocol": "TCP"},
        {"pid": 1234, "local_ip": "192.168.1.5", "local_port": 54321,
         "remote_ip": "8.8.8.8",       "remote_port": 53,  "protocol": "UDP"},
    ]

    def _clean(data, field_map):
        out = []
        for row in data:
            out.append({k: str(row.get(src, "N/A"))[:255] for k, src in field_map.items()})
        return out

    def prepare_data_for_gui(procs, conns):
        p = _clean(procs, {"pid":"pid","name":"name","ppid":"ppid","time":"time"})
        c = _clean(conns, {"pid":"pid","local_ip":"local_ip","local_port":"local_port", "remote_ip":"remote_ip","remote_port":"remote_port","protocol":"protocol"})
        suspicious = sum(1 for x in p if any(k in x["name"].lower() for k in ("malware","virus","rootkit","hidden","unknown")))
        return {"processes": p, "connections": c, "stats": {"total_processes": len(p), "total_connections": len(c), "suspicious_count": suspicious}}

    def search_in_prepared_data(prepared, term):
        t = term.lower()
        def match_p(r):
            return any(t in str(r.get(f,"")).lower() for f in ("pid","name","ppid","time"))
        def match_c(r):
            return any(t in str(r.get(f,"")).lower() for f in ("pid","local_ip","local_port","remote_ip","remote_port","protocol"))
        fp = [r for r in prepared["processes"] if match_p(r)]
        fc = [r for r in prepared["connections"] if match_c(r)]
        sus = sum(1 for x in fp if any(k in x["name"].lower() for k in ("malware","virus","rootkit","hidden","unknown")))
        return {"processes": fp, "connections": fc,"stats": {"total_processes": len(fp),"total_connections": len(fc),"suspicious_count": sus}}


# Theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

FONT_MONO   = ("Courier New", 12)
FONT_LABEL  = ("Courier New", 11)
FONT_HEADER = ("Courier New", 13, "bold")
FONT_STAT   = ("Courier New", 10)

BG_MAIN   = "#0d0d0d"
BG_PANEL  = "#141414"
BG_TABLE  = "#0a0a0a"
FG_TEXT   = "#d4d4d4"
FG_DIM    = "#6b6b6b"
FG_ACCENT = "#c8c8c8"
ALERT_RED = "#c0392b"
BORDER    = "#2a2a2a"

PROC_COLS  = ("PID", "Name", "PPID", "Time")
CONN_COLS  = ("PID", "Local IP", "Local Port", "Remote IP", "Remote Port", "Protocol")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _style_treeview(tree: ttk.Treeview, col_widths: dict):
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Forensics.Treeview",
                    background=BG_TABLE,
                    foreground=FG_TEXT,
                    fieldbackground=BG_TABLE,
                    bordercolor=BORDER,
                    rowheight=24,
                    font=FONT_MONO)
    style.configure("Forensics.Treeview.Heading",
                    background=BG_PANEL,
                    foreground=FG_ACCENT,
                    relief="flat",
                    font=FONT_HEADER)
    style.map("Forensics.Treeview",
              background=[("selected", "#1e1e1e")],
              foreground=[("selected", "#ffffff")])
    tree.configure(style="Forensics.Treeview")
    for col, w in col_widths.items():
        tree.column(col, width=w, anchor="w", minwidth=60)
        tree.heading(col, text=col)


def _tag_suspicious_rows(tree: ttk.Treeview):
    tree.tag_configure("suspicious", foreground=ALERT_RED)


# Main Application

class ForensicsApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Memory Forensics Tool  —  v1.0")
        self.geometry("1100x700")
        self.minsize(900, 560)
        self.configure(fg_color=BG_MAIN)

        self._prepared_data = None
        self._build_ui()
        self._load_data()

    # UI Construction

    def _build_ui(self):
        # Top bar 
        top = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0, height=48)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="MEMORY FORENSICS", font=("Courier New", 14, "bold"), text_color=FG_ACCENT).pack(side="left", padx=16, pady=12)

        self._status_label = ctk.CTkLabel(top, text="", font=FONT_STAT, text_color=FG_DIM)
        self._status_label.pack(side="left", padx=8)

        # Reload button
        ctk.CTkButton(top, text="Reload", width=80, height=28, font=FONT_LABEL, fg_color="#1e1e1e", hover_color="#2a2a2a",
                      border_color=BORDER, border_width=1, text_color=FG_TEXT,
                      command=self._load_data).pack(side="right", padx=12, pady=10)

        # Stats bar 
        stats_row = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0, height=36)
        stats_row.pack(fill="x", side="top", padx=0)

        self._lbl_procs = ctk.CTkLabel(stats_row, text="Processes: —",
                                        font=FONT_STAT, text_color=FG_DIM)
        self._lbl_procs.pack(side="left", padx=16, pady=8)

        self._lbl_conns = ctk.CTkLabel(stats_row, text="Connections: —",
                                        font=FONT_STAT, text_color=FG_DIM)
        self._lbl_conns.pack(side="left", padx=16)

        self._lbl_sus = ctk.CTkLabel(stats_row, text="Suspicious: —",
                                      font=FONT_STAT, text_color=ALERT_RED)
        self._lbl_sus.pack(side="left", padx=16)

        # Search bar 
        search_row = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0, height=40)
        search_row.pack(fill="x", side="top", padx=12, pady=(4, 0))

        ctk.CTkLabel(search_row, text="Search:", font=FONT_LABEL,
                     text_color=FG_DIM).pack(side="left", padx=(4, 6))

        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", self._on_search_change)
        search_entry = ctk.CTkEntry(search_row, textvariable=self._search_var,
                                    width=320, height=28,
                                    font=FONT_MONO, fg_color="#0f0f0f",
                                    border_color=BORDER, text_color=FG_TEXT,
                                    placeholder_text="pid, name, ip, port...",
                                    placeholder_text_color=FG_DIM)
        search_entry.pack(side="left")

        ctk.CTkButton(search_row, text="Clear", width=60, height=28,
                      font=FONT_LABEL, fg_color="#1a1a1a", hover_color="#2a2a2a",
                      border_color=BORDER, border_width=1, text_color=FG_DIM,
                      command=self._clear_search).pack(side="left", padx=8)

        # Tabbed tables 
        tab_view = ctk.CTkTabview(self, fg_color=BG_PANEL,
                                  segmented_button_fg_color=BG_PANEL,
                                  segmented_button_selected_color="#1e1e1e",
                                  segmented_button_selected_hover_color="#2a2a2a",
                                  segmented_button_unselected_color=BG_PANEL,
                                  segmented_button_unselected_hover_color="#181818",
                                  text_color=FG_TEXT,
                                  border_color=BORDER, border_width=1)
        tab_view.pack(fill="both", expand=True, padx=12, pady=8)

        tab_proc = tab_view.add("Processes")
        tab_conn = tab_view.add("Connections")

        self._proc_tree  = self._build_table(tab_proc,  PROC_COLS,
                                              {c: w for c, w in zip(PROC_COLS, [80,200,80,120])})
        self._conn_tree  = self._build_table(tab_conn,  CONN_COLS,
                                              {c: w for c, w in zip(CONN_COLS, [80,140,100,140,100,90])})

        # Detail pane 
        detail_frame = ctk.CTkFrame(self, fg_color=BG_PANEL,
                                    corner_radius=0, height=80)
        detail_frame.pack(fill="x", side="bottom", padx=12, pady=(0, 8))
        detail_frame.pack_propagate(False)

        ctk.CTkLabel(detail_frame, text="Selected row",
                     font=FONT_STAT, text_color=FG_DIM).pack(anchor="nw", padx=10, pady=(6, 2))

        self._detail_var = tk.StringVar(value="—")
        ctk.CTkLabel(detail_frame, textvariable=self._detail_var,
                     font=FONT_MONO, text_color=FG_TEXT,
                     justify="left", wraplength=1060).pack(anchor="nw", padx=10)

        self._proc_tree.bind("<<TreeviewSelect>>",
                              lambda e: self._show_detail(self._proc_tree, PROC_COLS))
        self._conn_tree.bind("<<TreeviewSelect>>",
                              lambda e: self._show_detail(self._conn_tree, CONN_COLS))

    def _build_table(self, parent, columns, col_widths):
        frame = ctk.CTkFrame(parent, fg_color=BG_TABLE, corner_radius=0)
        frame.pack(fill="both", expand=True)

        tree = ttk.Treeview(frame, columns=columns, show="headings",
                            selectmode="browse")
        _style_treeview(tree, col_widths)
        _tag_suspicious_rows(tree)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    # Data Loading & Rendering

    def _load_data(self):
        self._set_status("loading...")
        try:
            self._prepared_data = prepare_data_for_gui(sample_processes, sample_connections)
            self._render(self._prepared_data)
            self._set_status("ready")
        except Exception as exc:
            self._set_status(f"error: {exc}")

    def _render(self, data):
        stats = data["stats"]
        self._lbl_procs.configure(text=f"Processes: {stats['total_processes']}")
        self._lbl_conns.configure(text=f"Connections: {stats['total_connections']}")
        self._lbl_sus.configure(text=f"Suspicious: {stats['suspicious_count']}")

        self._fill_tree(self._proc_tree, data["processes"], PROC_COLS,
                        suspicious_field="name",
                        suspicious_keywords=("malware","virus","rootkit","hidden","unknown"))
        self._fill_tree(self._conn_tree, data["connections"], CONN_COLS)

    def _fill_tree(self, tree: ttk.Treeview, rows, cols,
                   suspicious_field=None, suspicious_keywords=()):
        tree.delete(*tree.get_children())
        key_map = {c: c.lower().replace(" ", "_") for c in cols}
        # also handle column names that differ (e.g. "Local IP" -> "local_ip")
        col_keys = {
            "PID": "pid", "Name": "name", "PPID": "ppid", "Time": "time",
            "Local IP": "local_ip", "Local Port": "local_port",
            "Remote IP": "remote_ip", "Remote Port": "remote_port",
            "Protocol": "protocol"
        }
        for row in rows:
            values = tuple(row.get(col_keys.get(c, c.lower()), "N/A") for c in cols)
            tag = ""
            if suspicious_field:
                val = row.get(col_keys.get(suspicious_field, suspicious_field), "").lower()
                if any(k in val for k in suspicious_keywords):
                    tag = "suspicious"
            tree.insert("", "end", values=values, tags=(tag,) if tag else ())

    # Search

    def _on_search_change(self, *_):
        if self._prepared_data is None:
            return
        term = self._search_var.get().strip()
        filtered = search_in_prepared_data(self._prepared_data, term)
        self._render(filtered)

    def _clear_search(self):
        self._search_var.set("")

    # Detail pane

    def _show_detail(self, tree: ttk.Treeview, cols):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        parts = [f"{c}: {v}" for c, v in zip(cols, vals)]
        self._detail_var.set("  |  ".join(parts))

    # Status

    def _set_status(self, msg: str):
        self._status_label.configure(text=msg)
        self.update_idletasks()

# Entry point

if __name__ == "__main__":
    app = ForensicsApp()
    app.mainloop()