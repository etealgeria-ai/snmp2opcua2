"""Desktop window for the SNMP trap to OPC UA gateway (Tkinter, no extra packages).

    python -m snmp2opcua.gui -c config.yaml [--start]

The look follows high-performance HMI practice (ISA-101): a neutral grey console where
colour appears only when something needs attention. High-severity traps, rejections and
dropped traps get colour, and always with a text label as well.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - reported in main()
    tk = None  # type: ignore[assignment]

from .diagnostics import STATUS_LABEL, Check, report_text, run_diagnostics, summarize
from .gui_controller import GatewayController, TrapRequest, parse_varbind_lines
from .snmp_driver import DeviceDef, EventsAddress
from . import stations as stations_mod
from .ge_orbit import Remote, format_report
from .tag_csv import TagCsvError, read_tags, write_tags
from .usm import AUTH_PROTOCOLS, PRIV_PROTOCOLS, UsmUser

# Neutral console palette; colour is reserved for abnormal states
PANEL = "#D5D9DD"       # window background
SURFACE = "#EEF0F2"     # tiles, headings, tabs
FIELD = "#FFFFFF"       # tables and editors
INK = "#1E2830"
MUTED = "#56636E"
LINE = "#B4BCC3"
ACCENT = "#2F6690"      # running state, selection, primary action
ACCENT_DARK = "#24506F"
WARN = "#C98A00"
WARN_TINT = "#FBEFC6"
WARN_INK = "#7A5200"
ALARM = "#B3261E"
ALARM_TINT = "#F5D5D2"
STOPPED = "#8A949C"
CHANGE_TINT = "#DCE6EF"   # brief highlight of a value that just changed (answers "what moved?")

MAX_TRAPS = 5000
MAX_REJECTS = 2000
MAX_LOG_LINES = 3000
CUSTOM_USER = "Custom credentials"

TILES = [
    ("received", "Received"),
    ("published", "Published to OPC UA"),
    ("queued", "Waiting to publish"),
    ("rejected", "Rejected"),
    ("malformed", "Unreadable packets"),
    ("dropped", "Dropped"),
]
# Which counters are abnormal when non-zero, and how loud
TILE_ALERT = {"queued": WARN, "rejected": WARN, "malformed": WARN, "dropped": ALARM}


class GatewayApp:
    def __init__(self, root: tk.Tk, controller: GatewayController, autostart: bool = False):
        self.root = root
        self.ctl = controller
        self.traps: deque[dict] = deque(maxlen=MAX_TRAPS)
        self.trap_by_iid: dict[str, dict] = {}
        self.devices: dict[str, dict] = {}
        self.reject_count = 0
        self.paused = False
        self.unseen = 0
        self.seq = 0
        self.had_error = False
        self.restart_pending = False
        self.sending = False
        self.polling = False
        self.diag_running = False
        self.diag_checks: list[Check] = []
        self.diag_when: datetime | None = None
        self.diag_by_iid: dict[str, Check] = {}
        self.tag_values: dict[str, tuple[object, bool, str]] = {}   # path -> (value, good, time)
        self.tag_devices: list[DeviceDef] = []
        self.dynamic_types: dict[str, str] = {}          # polled tags not in the config (e.g. remote radios)
        self.config_tag_paths: set[str] = set()          # tags defined by the configuration
        self.radios: dict[str, dict] = {}                 # master path -> last "radios" payload
        self.station_list: list[stations_mod.Station] = []
        self.station_current: stations_mod.Station | None = None   # None = adding a new station
        self.station_dirty = False
        self.station_loading = False
        self.station_testing = False
        self.live: dict[str, dict] = {}                   # path -> value, good, dtype, source, updated, count, changed
        self.live_paused = False
        self.live_unseen = 0
        self.live_sort = ("tag", False)

        self._setup_style()
        self._build()
        self._load_config_into_ui(first=True)
        self._refresh_stations()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self._poll)
        root.after(1000, self._tick)
        if autostart:
            root.after(300, self.start)

    # ================================================================== styling
    def _setup_style(self) -> None:
        base = tkfont.nametofont("TkDefaultFont")
        family = base.actual("family")
        self.f_base = tkfont.Font(family=family, size=10)
        self.f_small = tkfont.Font(family=family, size=9)
        self.f_head = tkfont.Font(family=family, size=11, weight="bold")
        self.f_kpi = tkfont.Font(family=family, size=20, weight="bold")
        mono = tkfont.nametofont("TkFixedFont")
        self.f_mono = tkfont.Font(family=mono.actual("family"), size=10)

        self.root.configure(background=PANEL)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=PANEL, foreground=INK, font=self.f_base, bordercolor=LINE,
                        lightcolor=PANEL, darkcolor=PANEL, troughcolor=SURFACE, focuscolor=ACCENT,
                        fieldbackground=FIELD, selectbackground=ACCENT, selectforeground="#FFFFFF")
        style.configure("TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=INK)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Small.TLabel", foreground=MUTED, font=self.f_small)
        style.configure("Head.TLabel", font=self.f_head)
        style.configure("Error.TLabel", foreground=ALARM)
        style.configure("TNotebook", background=PANEL, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", padding=(14, 6), background=PANEL, foreground=MUTED, borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", SURFACE)], foreground=[("selected", INK)])
        style.configure("TButton", padding=(10, 4), background=SURFACE)
        style.map("TButton", background=[("disabled", PANEL), ("active", "#E1E5E9")],
                  foreground=[("disabled", STOPPED)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#FFFFFF", bordercolor=ACCENT_DARK)
        style.map("Accent.TButton", background=[("disabled", "#9DB3C6"), ("active", ACCENT_DARK)],
                  foreground=[("disabled", "#EEF3F7")])
        rowheight = int(self.f_base.metrics("linespace") * 1.7)
        style.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=INK,
                        rowheight=rowheight, borderwidth=0)
        # Mapping only the selected state keeps per-row tag colours visible on Tk 8.6.9+
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=SURFACE, foreground=MUTED, font=self.f_small,
                        relief="flat", padding=(6, 4))
        style.map("Treeview.Heading", background=[("active", "#E1E5E9")])
        style.configure("TLabelframe", background=PANEL, bordercolor=LINE)
        style.configure("TLabelframe.Label", background=PANEL, foreground=MUTED)
        style.configure("TCheckbutton", background=PANEL)
        style.configure("TRadiobutton", background=PANEL)

    # ================================================================== layout
    def _build(self) -> None:
        root = self.root

        # --- toolbar: actions on the left, state on the right
        bar = ttk.Frame(root, padding=(12, 10, 12, 4))
        bar.pack(side="top", fill="x")
        self.btn_start = ttk.Button(bar, text="Start gateway", style="Accent.TButton", command=self.start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(bar, text="Stop gateway", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=(6, 0))
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=12)
        ttk.Button(bar, text="Open config…", command=self.open_config).pack(side="left")
        self.config_label = ttk.Label(bar, text=str(self.ctl.config_path), style="Muted.TLabel")
        self.config_label.pack(side="left", padx=(8, 0))

        self.status_text = ttk.Label(bar, text="Stopped", style="Head.TLabel")
        self.status_text.pack(side="right")
        self.status_dot = tk.Canvas(bar, width=14, height=14, highlightthickness=0, background=PANEL)
        self.status_dot.pack(side="right", padx=(0, 6))
        self.dot = self.status_dot.create_oval(2, 2, 12, 12, fill=STOPPED, outline="")

        # --- where traps come from and where they go
        info = ttk.Frame(root, padding=(12, 0, 12, 8))
        info.pack(side="top", fill="x")
        self.info_listen = ttk.Label(info, text="", style="Muted.TLabel")
        self.info_listen.pack(side="left")
        self.info_opcua = ttk.Label(info, text="", style="Muted.TLabel")
        self.info_opcua.pack(side="left", padx=(24, 0))

        # --- counters
        strip = ttk.Frame(root, padding=(12, 0, 12, 10))
        strip.pack(side="top", fill="x")
        self.tiles: dict[str, tuple[tk.Frame, tk.Label, tk.Label, str]] = {}
        for i, (key, caption) in enumerate(TILES):
            tile = tk.Frame(strip, background=SURFACE, highlightthickness=1, highlightbackground=LINE)
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            strip.columnconfigure(i, weight=1, uniform="tiles")
            stripe = tk.Frame(tile, width=4, background=SURFACE)
            stripe.pack(side="left", fill="y")
            inner = tk.Frame(tile, background=SURFACE)
            inner.pack(side="left", fill="both", expand=True, padx=10, pady=6)
            num = tk.Label(inner, text="–", font=self.f_kpi, background=SURFACE, foreground=INK, anchor="w")
            num.pack(fill="x")
            cap = tk.Label(inner, text=caption, font=self.f_small, background=SURFACE, foreground=MUTED, anchor="w")
            cap.pack(fill="x")
            self.tiles[key] = (stripe, num, cap, caption)

        # --- status line (packed before the notebook so it stays visible when resizing)
        self.status_line = ttk.Label(root, text="", style="Small.TLabel", padding=(12, 4, 12, 6))
        self.status_line.pack(side="bottom", fill="x")

        self.nb = ttk.Notebook(root)
        self.nb.pack(side="top", fill="both", expand=True, padx=12)
        self.tab_traps = self._build_traps_tab()
        self.tab_live = self._build_live_tab()
        self.tab_tags = self._build_tags_tab()
        self.tab_radios = self._build_radios_tab()
        self.tab_devices = self._build_devices_tab()
        self.tab_rejected = self._build_rejected_tab()
        self.tab_diag = self._build_diag_tab()
        self.tab_stations = self._build_stations_tab()
        self.tab_test = self._build_test_tab()
        self.tab_config = self._build_config_tab()
        self.tab_log = self._build_log_tab()
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _make_tree(self, parent: ttk.Frame, columns: list[tuple[str, str, int, bool]]) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for cid, heading, width, stretch in columns:
            tree.heading(cid, text=heading, anchor="w")
            tree.column(cid, width=width, minwidth=40, stretch=stretch, anchor="w")
        ys = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    def _text_box(self, parent: ttk.Frame, height: int, readonly: bool,
                  wrap: Literal["none", "char", "word"] = "none") -> tk.Text:
        text = tk.Text(parent, height=height, font=self.f_mono, wrap=wrap, background=FIELD, foreground=INK,
                       insertbackground=INK, relief="flat", borderwidth=0, highlightthickness=1,
                       highlightbackground=LINE, highlightcolor=ACCENT, padx=8, pady=6, undo=not readonly)
        ys = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=ys.set)
        text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        if wrap == "none":
            xs = ttk.Scrollbar(parent, orient="horizontal", command=text.xview)
            text.configure(xscrollcommand=xs.set)
            xs.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        if readonly:
            text.configure(state="disabled")
        return text

    # ------------------------------------------------------------------ traps tab
    def _build_traps_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Traps")

        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._refilter())
        ttk.Entry(bar, textvariable=self.filter_var, width=34).pack(side="left", padx=(6, 0))
        self.trap_count_label = ttk.Label(bar, text="", style="Muted.TLabel")
        self.trap_count_label.pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Export CSV…", command=self.export_csv).pack(side="right")
        ttk.Button(bar, text="Clear", command=self.clear_traps).pack(side="right", padx=(0, 6))
        self.btn_pause = ttk.Button(bar, text="Pause feed", command=self.toggle_pause)
        self.btn_pause.pack(side="right", padx=(0, 6))

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(side="top", fill="both", expand=True)
        top = ttk.Frame(pane)
        self.trap_tree = self._make_tree(top, [
            ("time", "Time", 80, False), ("source", "Source", 130, False), ("version", "Version", 64, False),
            ("user", "v3 user", 100, False), ("trap", "Trap", 220, True), ("description", "Description", 220, True),
            ("severity", "Severity", 110, False), ("varbinds", "Variables", 380, True)])
        self.trap_tree.tag_configure("high", background=ALARM_TINT)
        self.trap_tree.tag_configure("medium", background=WARN_TINT)
        self.trap_tree.bind("<<TreeviewSelect>>", self._show_trap_detail)
        self.empty_traps = tk.Label(top, background=FIELD, foreground=MUTED, font=self.f_base, justify="center")
        self.empty_traps.place(relx=0.5, rely=0.5, anchor="center")
        pane.add(top, weight=3)

        bottom = ttk.Frame(pane, padding=(0, 8, 0, 0))
        self.trap_detail = self._text_box(bottom, height=9, readonly=True)
        pane.add(bottom, weight=1)
        return tab

    # ------------------------------------------------------------------ live data tab
    LIVE_VIEWS = ["All tags", "Changed in the last minute", "Bad quality", "Trap tags", "Polled tags",
                  "Gateway objects"]

    def _build_live_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Live data")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Filter").pack(side="left")
        self.live_filter = tk.StringVar()
        self.live_filter.trace_add("write", lambda *_: self._rebuild_live())
        ttk.Entry(bar, textvariable=self.live_filter, width=30).pack(side="left", padx=(6, 0))
        self.live_view = tk.StringVar(value=self.LIVE_VIEWS[0])
        view = ttk.Combobox(bar, textvariable=self.live_view, values=self.LIVE_VIEWS, state="readonly", width=26)
        view.pack(side="left", padx=(10, 0))
        view.bind("<<ComboboxSelected>>", lambda _e: self._rebuild_live())
        self.live_count = ttk.Label(bar, text="", style="Muted.TLabel")
        self.live_count.pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Export snapshot CSV…", command=self.export_live).pack(side="right")
        self.btn_live_pause = ttk.Button(bar, text="Pause", command=self.toggle_live_pause)
        self.btn_live_pause.pack(side="right", padx=(0, 6))

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(side="top", fill="both", expand=True)
        top = ttk.Frame(pane)
        cols = [("tag", "Tag", 360, True), ("value", "Value", 300, True), ("type", "Data type", 80, False),
                ("quality", "Quality", 70, False), ("updated", "Updated", 90, False), ("updates", "Updates", 70, False),
                ("source", "Source", 80, False)]
        self.live_tree = self._make_tree(top, cols)
        for cid, heading, _w, _s in cols:
            self.live_tree.heading(cid, text=heading, anchor="w", command=self._live_sorter(cid))
        self.live_tree.tag_configure("bad", background=WARN_TINT)
        self.live_tree.tag_configure("changed", background=CHANGE_TINT)
        self.live_tree.bind("<<TreeviewSelect>>", self._show_live_detail)
        self.empty_live = tk.Label(top, background=FIELD, foreground=MUTED, font=self.f_base, justify="center",
                                   text="No tags yet.\nStart the gateway to see every tag it publishes, live.")
        self.empty_live.place(relx=0.5, rely=0.5, anchor="center")
        pane.add(top, weight=4)

        bottom = ttk.Frame(pane, padding=(0, 8, 0, 0))
        head = ttk.Frame(bottom)
        head.pack(side="top", fill="x")
        self.live_nodeid = ttk.Label(head, text="Select a tag to see its OPC UA NodeId and full value.",
                                     style="Muted.TLabel")
        self.live_nodeid.pack(side="left")
        ttk.Button(head, text="Copy NodeId", command=self.copy_live_nodeid).pack(side="right")
        box = ttk.Frame(bottom)
        box.pack(side="top", fill="both", expand=True, pady=(6, 0))
        self.live_detail = self._text_box(box, height=4, readonly=True, wrap="word")
        pane.add(bottom, weight=1)
        return tab

    @staticmethod
    def _source_label(source: str) -> str:
        return {"trap": "Trap", "poll": "Poll", "gateway": "Gateway"}.get(source, source)

    def _live_matches(self, path: str, e: dict) -> bool:
        needle = self.live_filter.get().strip().lower()
        if needle and needle not in path.lower() and needle not in self._fmt_value(e["value"]).lower():
            return False
        view = self.live_view.get()
        if view == "Changed in the last minute":
            return e["changed"] is not None and time.monotonic() - e["changed"] <= 60
        if view == "Bad quality":
            return not e["good"]
        if view == "Trap tags":
            return e["source"] == "trap"
        if view == "Polled tags":
            return e["source"] == "poll"
        if view == "Gateway objects":
            return e["source"] == "gateway"
        return True

    def _live_row(self, path: str, e: dict) -> tuple:
        when = e["updated"].strftime("%H:%M:%S") if e["updated"] else ""
        return (path, self._fmt_value(e["value"]), e["dtype"], "Good" if e["good"] else "Bad", when,
                e["count"], self._source_label(e["source"]))

    def _live_tags(self, e: dict) -> tuple[str, ...]:
        if not e["good"]:
            return ("bad",)
        if e["changed"] is not None and time.monotonic() - e["changed"] < 2.0:
            return ("changed",)
        return ()

    def _live_sorter(self, column: str):
        def sort() -> None:
            self._live_sort_by(column)
        return sort

    def _live_sort_by(self, column: str) -> None:
        col, desc = self.live_sort
        self.live_sort = (column, not desc if col == column else column in ("updated", "updates"))
        self._rebuild_live()

    def _rebuild_live(self) -> None:
        tree = self.live_tree
        selected = tree.selection()
        tree.delete(*tree.get_children())
        col, desc = self.live_sort
        keys = {"tag": lambda kv: kv[0].lower(), "value": lambda kv: self._fmt_value(kv[1]["value"]).lower(),
                "type": lambda kv: kv[1]["dtype"], "quality": lambda kv: kv[1]["good"],
                "updated": lambda kv: kv[1]["updated"] or datetime.min, "updates": lambda kv: kv[1]["count"],
                "source": lambda kv: kv[1]["source"]}
        rows = sorted(((p, e) for p, e in self.live.items() if self._live_matches(p, e)),
                      key=keys.get(col, keys["tag"]), reverse=desc)
        for path, e in rows:
            tree.insert("", "end", iid=f"lv:{path}", values=self._live_row(path, e), tags=self._live_tags(e))
        if selected and tree.exists(selected[0]):
            tree.selection_set(selected[0])
        self._update_live_count(len(rows))

    def _update_live_count(self, shown: int | None = None) -> None:
        shown = len(self.live_tree.get_children()) if shown is None else shown
        total = len(self.live)
        bad = sum(1 for e in self.live.values() if not e["good"])
        self.live_count.configure(text=(f"Showing {shown:,} of {total:,} tags" + (f", {bad:,} with Bad quality"
                                                                                  if bad else "")) if total else "")
        if total:
            self.empty_live.place_forget()
        else:
            self.empty_live.place(relx=0.5, rely=0.5, anchor="center")

    def _on_catalog(self, items: list) -> None:
        self.live = {}
        for path, value, good, dtype, source in items:
            self.live[path] = {"value": value, "good": good, "dtype": dtype, "source": source, "updated": None,
                               "count": 0, "changed": None}
        self._rebuild_live()

    def _live_ingest(self, updates: list) -> None:
        now = datetime.now()
        mono = time.monotonic()
        added = False
        for item in updates:
            path, value, good = item[0], item[1], item[2]
            dtype = item[3] if len(item) > 3 else ""
            source = item[4] if len(item) > 4 else ("gateway" if path.startswith("Gateway.") else "trap")
            e = self.live.get(path)
            if e is None:
                e = self.live[path] = {"value": None, "good": good, "dtype": dtype, "source": source,
                                       "updated": None, "count": 0, "changed": None}
                added = True
            if e["value"] != value or e["good"] != good:
                e["changed"] = mono
            e.update(value=value, good=good, updated=now, count=e["count"] + 1)
            if dtype:
                e["dtype"] = dtype
            if self.live_paused:
                self.live_unseen += 1
                continue
            iid = f"lv:{path}"
            if self.live_tree.exists(iid):
                self.live_tree.item(iid, values=self._live_row(path, e), tags=self._live_tags(e))
            elif self._live_matches(path, e):
                added = True
        if self.live_paused:
            self.btn_live_pause.configure(text=f"Resume ({self.live_unseen:,} updates)")
        elif added:
            self._rebuild_live()
        else:
            self._update_live_count()
        if self.live_tree.selection() and not self.live_paused:
            self._show_live_detail()

    def _live_tick(self) -> None:
        """Clear change highlights after 2 s; keep the 'changed in the last minute' view current."""
        if self.live_paused or not self.live:
            return
        if self.live_view.get() == "Changed in the last minute":
            self._rebuild_live()
            return
        mono = time.monotonic()
        for path, e in self.live.items():
            if e["changed"] is not None and 2.0 <= mono - e["changed"] < 3.5:
                iid = f"lv:{path}"
                if self.live_tree.exists(iid):
                    self.live_tree.item(iid, tags=self._live_tags(e))

    def toggle_live_pause(self) -> None:
        self.live_paused = not self.live_paused
        if self.live_paused:
            self.live_unseen = 0
            self.btn_live_pause.configure(text="Resume")
        else:
            self.btn_live_pause.configure(text="Pause")
            self._rebuild_live()

    def _selected_live(self) -> str | None:
        sel = self.live_tree.selection()
        return sel[0][3:] if sel else None

    def _show_live_detail(self, _event=None) -> None:
        path = self._selected_live()
        e = self.live.get(path) if path else None
        if path is None or e is None:
            return
        self.live_nodeid.configure(text=f"ns=2;s={path}   ({e['dtype']}, {self._source_label(e['source'])}, "
                                        f"{'Good' if e['good'] else 'Bad'} quality, {e['count']:,} updates)",
                                   style="TLabel")
        self.live_detail.configure(state="normal")
        self.live_detail.delete("1.0", "end")
        self.live_detail.insert("1.0", self._fmt_value(e["value"]))
        self.live_detail.configure(state="disabled")

    def copy_live_nodeid(self) -> None:
        path = self._selected_live()
        if path is None:
            self.status_line.configure(text="Select a tag first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(f"ns=2;s={path}")
        self.status_line.configure(text=f"Copied ns=2;s={path} (namespace index 2 is the usual value).")

    def export_live(self) -> None:
        rows = [(p, e) for p, e in sorted(self.live.items()) if self._live_matches(p, e)]
        if not rows:
            messagebox.showinfo("Export snapshot", "There are no tags to export.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export live data snapshot",
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile=f"snmp2opcua-live-{datetime.now():%Y%m%d-%H%M%S}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["Tag", "NodeId", "Value", "Data Type", "Quality", "Updated", "Updates", "Source"])
                for p, e in rows:
                    w.writerow([p, f"ns=2;s={p}", self._fmt_value(e["value"]), e["dtype"],
                                "Good" if e["good"] else "Bad",
                                e["updated"].isoformat(timespec="seconds") if e["updated"] else "", e["count"],
                                self._source_label(e["source"])])
        except OSError as exc:
            messagebox.showerror("Export snapshot", f"Couldn't write {path}: {exc}", parent=self.root)
            return
        self.status_line.configure(text=f"Exported {len(rows):,} tags to {path}")

    # ------------------------------------------------------------------ tags tab
    def _build_tags_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Tags")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Filter").pack(side="left")
        self.tag_filter = tk.StringVar()
        self.tag_filter.trace_add("write", lambda *_: self._rebuild_tag_tree())
        ttk.Entry(bar, textvariable=self.tag_filter, width=28).pack(side="left", padx=(6, 0))
        self.tag_show_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Show table fields and the whole events queue", variable=self.tag_show_all,
                        command=self._rebuild_tag_tree).pack(side="left", padx=(14, 0))
        ttk.Button(bar, text="Export tags CSV…", command=self.export_tags).pack(side="right")
        ttk.Button(bar, text="Import tags CSV…", command=self.import_tags).pack(side="right", padx=(0, 6))
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        tree = ttk.Treeview(box, columns=["address", "type", "value", "quality", "updated"], show="tree headings",
                            selectmode="browse")
        tree.heading("#0", text="Name", anchor="w")
        tree.column("#0", width=260, minwidth=120, stretch=False, anchor="w")
        for cid, head, width, stretch in (("address", "Address", 330, False), ("type", "Data type", 80, False),
                                          ("value", "Value", 360, True), ("quality", "Quality", 70, False),
                                          ("updated", "Updated", 90, False)):
            tree.heading(cid, text=head, anchor="w")
            tree.column(cid, width=width, minwidth=50, stretch=stretch, anchor="w")
        ys = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        tree.tag_configure("device", font=self.f_head)
        tree.tag_configure("bad", background=WARN_TINT)
        self.tag_tree = tree
        self.empty_tags = tk.Label(box, background=FIELD, foreground=MUTED, font=self.f_base, justify="center",
                                   text="No devices configured.\nAdd channels and devices with trap tags in the "
                                        "Configuration tab (see the README), or import a tags CSV.")
        self.empty_tags.place(relx=0.5, rely=0.5, anchor="center")
        self.tag_info = ttk.Label(tab, text="", style="Small.TLabel", wraplength=900, justify="left")
        self.tag_info.pack(side="top", fill="x", pady=(6, 0))
        tree.bind("<<TreeviewSelect>>", self._on_tag_select)
        return tab

    @staticmethod
    def _shown_by_default(tag) -> bool:
        a = tag.address
        if isinstance(a, EventsAddress):
            return a.event is None or (a.event == 1 and a.field_no is None)
        return not tag.auto or a.index is None

    @staticmethod
    def _fmt_value(value) -> str:
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, datetime):
            return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(value, float):
            return f"{value:g}"
        return "" if value is None else str(value)

    def _rebuild_tag_tree(self) -> None:
        tree = self.tag_tree
        tree.delete(*tree.get_children())
        needle = self.tag_filter.get().strip().lower()
        channels: dict[str, str] = {}
        for dev in self.tag_devices:
            ch_iid = channels.get(dev.channel)
            if ch_iid is None:
                ch_iid = channels[dev.channel] = f"ch:{dev.channel}"
                tree.insert("", "end", iid=ch_iid, text=dev.channel, open=True, tags=("device",),
                            values=("", "", "", "", ""))
            proto = f"{dev.protocol} {dev.port}" if dev.trap_enabled else "traps disabled"
            dev_iid = f"dev:{dev.path}"
            tree.insert(ch_iid, "end", iid=dev_iid, text=dev.name, open=True, tags=("device",),
                        values=(f"{dev.host}   SNMP v{dev.snmp_version}   {proto}", "", "", "", ""))
            for tag in dev.tags:
                if not (self.tag_show_all.get() or self._shown_by_default(tag)):
                    continue
                path = dev.tag_path(tag)
                if needle and needle not in path.lower() and needle not in tag.address.text().lower():
                    continue
                initial = {"Boolean": False, "String": "", "Long": 0, "DWord": 0, "Float": 0.0, "Double": 0.0,
                           "Date": ""}[tag.data_type]
                value, good, when = self.tag_values.get(path, (initial, True, ""))
                tree.insert(dev_iid, "end", iid=f"tag:{path}", text=tag.name, tags=() if good else ("bad",),
                            values=(tag.address.text(), tag.data_type, self._fmt_value(value),
                                    "Good" if good else "Bad", when))
        for path, data_type in list(self.dynamic_types.items()):
            if not needle or needle in path.lower():
                if not tree.exists(f"tag:{path}") and self._ensure_dynamic_row(path, data_type):
                    value, good, when = self.tag_values.get(path, ("", True, ""))
                    tree.item(f"tag:{path}", values=("(polled)", data_type, self._fmt_value(value),
                                                     "Good" if good else "Bad", when), tags=() if good else ("bad",))
        if self.tag_devices:
            self.empty_tags.place_forget()
        else:
            self.empty_tags.place(relx=0.5, rely=0.5, anchor="center")
        n = sum(len(d.tags) for d in self.tag_devices)
        self.nb.tab(self.tab_tags, text=f"Tags ({n:,})" if n else "Tags")

    def _ensure_dynamic_row(self, path: str, data_type: str) -> bool:
        """Add a row for a polled tag that isn't in the config (e.g. a newly seen remote radio)."""
        dev = next((d for d in self.tag_devices if path.startswith(d.path + ".")), None)
        if dev is None or not self.tag_tree.exists(f"dev:{dev.path}"):
            return False
        self.dynamic_types[path] = data_type
        parent = f"dev:{dev.path}"
        segments = path[len(dev.path) + 1:].split(".")
        prefix = dev.path
        for seg in segments[:-1]:
            prefix += "." + seg
            gid = f"grp:{prefix}"
            if not self.tag_tree.exists(gid):
                self.tag_tree.insert(parent, "end", iid=gid, text=seg, open=not prefix.endswith(".Remotes") and
                                     ".Remotes." not in prefix, values=("", "", "", "", ""))
            parent = gid
        self.tag_tree.insert(parent, "end", iid=f"tag:{path}", text=segments[-1],
                             values=("(polled)", data_type, "", "", ""))
        return True

    def _on_tags(self, updates: list) -> None:
        self._live_ingest(updates)
        now = datetime.now().strftime("%H:%M:%S")
        for path, value, good, *rest in updates:
            self.tag_values[path] = (value, good, now)
            iid = f"tag:{path}"
            if not self.tag_tree.exists(iid) and rest and path not in self.config_tag_paths:
                self._ensure_dynamic_row(path, rest[0])      # e.g. a newly seen remote radio
            if self.tag_tree.exists(iid):
                row = self.tag_tree.item(iid)["values"]
                self.tag_tree.item(iid, values=(row[0], row[1], self._fmt_value(value), "Good" if good else "Bad",
                                                now), tags=() if good else ("bad",))

    def _selected_device(self) -> DeviceDef | None:
        sel = self.tag_tree.selection()
        if not sel:
            return self.tag_devices[0] if len(self.tag_devices) == 1 else None
        iid = sel[0]
        for dev in self.tag_devices:
            if iid == f"dev:{dev.path}" or iid.startswith(f"tag:{dev.path}."):
                return dev
        return None

    def _on_tag_select(self, _event=None) -> None:
        dev = self._selected_device()
        if dev is None:
            self.tag_info.configure(text="")
            return
        comm = "Custom Community set" if dev.community else "any community"
        sec = f"v3 user {dev.v3_user.name} ({dev.v3_user.level})" if dev.v3_user else comm
        ascii_note = ", extended ASCII" if dev.extended_ascii else ""
        self.tag_info.configure(text=f"{dev.path}: traps from {dev.host}, SNMP v{dev.snmp_version}, {sec}, "
                                     f"{dev.protocol} port {dev.port}, {dev.number_of_events} events of "
                                     f"{dev.number_of_fields} fields{ascii_note}.")

    def export_tags(self) -> None:
        dev = self._selected_device()
        if dev is None:
            messagebox.showinfo("Export tags", "Select a device (or one of its tags) first.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title=f"Export tags of {dev.path}",
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile=f"{dev.channel}_{dev.name}_tags.csv")
        if not path:
            return
        try:
            n = write_tags(dev.tags, path)
        except OSError as exc:
            messagebox.showerror("Export tags", f"Couldn't write {path}: {exc}", parent=self.root)
            return
        self.status_line.configure(text=f"Exported {n} tags of {dev.path} to {path} (auto-created tags left out)")

    def _device_cfg(self, dev: DeviceDef) -> dict | None:
        for c in (self.ctl.cfg or {}).get("channels") or []:
            if c.get("name") == dev.channel:
                return next((d for d in c.get("devices") or [] if d.get("name") == dev.name), None)
        return None

    def import_tags(self) -> None:
        dev = self._selected_device()
        if dev is None:
            messagebox.showinfo("Import tags", "Select the device to import into first.", parent=self.root)
            return
        raw = self._device_cfg(dev) or {}
        target = raw.get("tags_csv")
        if not target:
            messagebox.showinfo("Import tags", f"Add a line  tags_csv: {dev.channel}_{dev.name}_tags.csv  to device "
                                f"{dev.path} in the Configuration tab and save, then import again.", parent=self.root)
            return
        src = filedialog.askopenfilename(parent=self.root, title=f"Import tags into {dev.path}",
                                         filetypes=[("CSV", "*.csv"), ("All files", "*")])
        if not src:
            return
        try:
            tags, skipped = read_tags(src, dev.path)
        except (TagCsvError, OSError, UnicodeDecodeError) as exc:
            detail = "\n".join(exc.problems[:15]) if isinstance(exc, TagCsvError) else str(exc)
            messagebox.showerror("Import tags", f"Nothing was imported:\n{detail}", parent=self.root)
            return
        dest = Path(target)
        if not dest.is_absolute():
            dest = self.ctl.config_path.resolve().parent / dest
        try:
            if dest.exists():
                dest.with_suffix(dest.suffix + ".bak").write_bytes(dest.read_bytes())
            dest.write_text(Path(src).read_text(encoding="utf-8-sig"), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Import tags", f"Couldn't write {dest}: {exc}", parent=self.root)
            return
        note = f" {len(skipped)} rows without trap addresses were skipped." if skipped else ""
        self.status_line.configure(text=f"Imported {len(tags)} tags into {dest.name} for {dev.path}.{note} "
                                        f"Use Save and restart (Configuration tab) to apply.")

    # ------------------------------------------------------------------ radios tab
    def _build_radios_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Radios")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        self.radio_summary = ttk.Label(bar, text="Remote radios reported by GE MDS Orbit master stations, "
                                                 "weakest signal first.", style="Muted.TLabel")
        self.radio_summary.pack(side="left")
        ttk.Button(bar, text="Copy as report", command=self.copy_radio_report).pack(side="right")
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        self.radio_tree = self._make_tree(box, [
            ("master", "Master station", 170, False), ("mac", "Remote MAC", 150, False),
            ("ip", "Remote IP", 130, False), ("rssi", "RSSI (dBm)", 90, False), ("ifindex", "IfIndex", 70, False),
            ("status", "Status", 230, True), ("seen", "Last seen", 90, False), ("tag", "OPC UA tag", 100, False)])
        self.radio_tree.tag_configure("offline", background=ALARM_TINT)
        self.radio_tree.tag_configure("weak", background=WARN_TINT)
        self.empty_radios = tk.Label(box, background=FIELD, foreground=MUTED, font=self.f_base, justify="center",
                                     text="No radios yet.\nAdd polling with ge_orbit_remotes: true to the GE master "
                                          "station's device in the Configuration tab (see the README).")
        self.empty_radios.place(relx=0.5, rely=0.5, anchor="center")
        return tab

    def _on_radios(self, payload: dict) -> None:
        self.radios[payload["master"]] = payload
        tree = self.radio_tree
        tree.delete(*tree.get_children())
        rows = [r for p in self.radios.values() for r in p["rows"]]
        rows.sort(key=lambda r: (r["master"], r["rssi"] if r["rssi"] is not None else 999))
        for r in rows:
            tag: tuple[str, ...]
            if not r["poll_ok"]:
                status, tag = "Unknown, master not answering", ("offline",)
            elif not r["online"]:
                why = f"link {r['link']}" if r.get("listed", True) and r.get("link") else "not in master's table"
                status, tag = f"Offline, {why}", ("offline",)
            elif r["weak"]:
                status, tag = "Online, weak signal", ("weak",)
            else:
                status, tag = "Online", ()
            tree.insert("", "end", values=(r["master"], r["mac"], r["ip"], "N/A" if r["rssi"] is None else r["rssi"],
                                           r["if_index"], status, r["last_seen"], r.get("tag") or "none"),
                        tags=tag)
        if rows:
            self.empty_radios.place_forget()
        parts = []
        for master, p in self.radios.items():
            online = sum(r["online"] for r in p["rows"])
            state = "last poll OK" if p["ok"] else f"polling failed: {p['error']}"
            parts.append(f"{master}: {len(p['rows'])} remotes, {online} online, {state}")
        failing = any(not p["ok"] for p in self.radios.values())
        self.radio_summary.configure(text="; ".join(parts) + ".", style="Error.TLabel" if failing else "TLabel")
        offline = sum(1 for r in rows if not r["online"] or not r["poll_ok"])
        self.nb.tab(self.tab_radios, text=f"Radios ({len(rows)})" + (f" ⚠ {offline} offline" if offline else ""))

    def copy_radio_report(self) -> None:
        if not self.radios:
            self.radio_summary.configure(text="No radios to copy yet.", style="Muted.TLabel")
            return
        text = []
        for master, p in self.radios.items():
            remotes = [Remote(r["mac"], r["if_index"], r["ip"], r["rssi"]) for r in p["rows"] if r["online"]]
            text.append(f"{master}\n{format_report(remotes)}")
        self.root.clipboard_clear()
        self.root.clipboard_append("\n\n".join(text) + "\n")
        self.status_line.configure(text="Radio report copied to the clipboard.")

    # ------------------------------------------------------------------ devices tab
    def _build_devices_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Sources")
        self.device_tree = self._make_tree(tab, [
            ("source", "Source address", 170, False), ("count", "Traps", 80, False),
            ("last", "Last trap", 320, True), ("seen", "Last seen", 120, False), ("version", "Version", 80, False)])
        self.device_tree.tag_configure("high", background=ALARM_TINT)
        return tab

    # ------------------------------------------------------------------ rejected tab
    def _build_rejected_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Rejected")
        self.reject_tree = self._make_tree(tab, [
            ("time", "Time", 80, False), ("source", "Source", 140, False), ("kind", "Problem", 130, False),
            ("reason", "Reason", 700, True)])
        return tab

    # ------------------------------------------------------------------ diagnostics tab
    def _build_diag_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Diagnostics")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        self.btn_diag = ttk.Button(bar, text="Run checks", style="Accent.TButton", command=self.run_checks)
        self.btn_diag.pack(side="left")
        self.diag_summary = ttk.Label(bar, text="Checks the configuration, ports, SNMPv3, OPC UA and this computer.",
                                      style="Muted.TLabel")
        self.diag_summary.pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Save report…", command=self.save_report).pack(side="right")
        ttk.Button(bar, text="Copy report", command=self.copy_report).pack(side="right", padx=(0, 6))

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(side="top", fill="both", expand=True)
        top = ttk.Frame(pane)
        tree = ttk.Treeview(top, columns=["status", "result"], show="tree headings", selectmode="browse")
        tree.heading("#0", text="Check", anchor="w")
        tree.column("#0", width=280, minwidth=120, stretch=False, anchor="w")
        tree.heading("status", text="Status", anchor="w")
        tree.column("status", width=90, minwidth=60, stretch=False, anchor="w")
        tree.heading("result", text="Result", anchor="w")
        tree.column("result", width=640, minwidth=200, stretch=True, anchor="w")
        ys = ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=ys.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        tree.tag_configure("problem", background=ALARM_TINT)
        tree.tag_configure("warn", background=WARN_TINT)
        tree.tag_configure("section", font=self.f_head)
        tree.bind("<<TreeviewSelect>>", self._show_diag_detail)
        self.diag_tree = tree
        pane.add(top, weight=3)

        bottom = ttk.Frame(pane, padding=(0, 8, 0, 0))
        self.diag_detail = self._text_box(bottom, height=5, readonly=True, wrap="word")
        self.diag_detail.configure(font=self.f_base)
        self.diag_detail.tag_configure("head", font=self.f_head)
        pane.add(bottom, weight=1)
        self._set_diag_detail([("Select a check to see what was found and how to fix it.", "")])
        return tab

    # ------------------------------------------------------------------ stations tab
    STATION_FIELDS = ["channel", "name", "ip", "community", "version", "port", "scan_rate_s", "timeout_ms",
                      "retries", "max_repetitions", "rssi_warning_dbm", "remote_tags", "remote_tag_prefix"]
    STATION_FLAGS = ["rssi_enabled", "receive_traps", "auto_create_tags"]

    def _build_stations_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Stations")
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(0, weight=1)

        # left: the list of GE master stations
        left = ttk.Frame(tab)
        left.grid(row=0, column=0, sticky="nsw", padx=(0, 16))
        ttk.Label(left, text="GE MDS Orbit master stations", style="Head.TLabel").pack(side="top", anchor="w")
        lbox = ttk.Frame(left)
        lbox.pack(side="top", fill="both", expand=True, pady=(6, 6))
        self.station_tree = self._make_tree(lbox, [("station", "Station", 190, True), ("ip", "IP address", 120, False)])
        self.station_tree.bind("<<TreeviewSelect>>", self._on_station_select)
        btns = ttk.Frame(left)
        btns.pack(side="top", fill="x")
        ttk.Button(btns, text="Add station", command=self.add_station).pack(side="left")
        self.btn_remove_station = ttk.Button(btns, text="Remove", command=self.remove_station)
        self.btn_remove_station.pack(side="left", padx=(6, 0))

        # right: the form
        right = ttk.Frame(tab)
        right.grid(row=0, column=1, sticky="nsew")
        self.station_title = ttk.Label(right, text="", style="Head.TLabel")
        self.station_title.pack(side="top", anchor="w", pady=(0, 8))
        self.sv: dict[str, tk.StringVar] = {k: tk.StringVar() for k in self.STATION_FIELDS}
        self.sb: dict[str, tk.BooleanVar] = {k: tk.BooleanVar() for k in self.STATION_FLAGS}
        for var in [*self.sv.values(), *self.sb.values()]:
            var.trace_add("write", lambda *_: self._mark_station_dirty())
        self.station_entries: dict[str, ttk.Entry | ttk.Combobox] = {}

        def section(title: str) -> ttk.Labelframe:
            f = ttk.Labelframe(right, text=title, padding=(12, 8))
            f.pack(side="top", fill="x", pady=(0, 10))
            f.columnconfigure(1, weight=1)
            return f

        def row(parent, r: int, label: str, key: str, width: int = 24, hint: str = "", combo=None, show=""):
            ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=(0, 12), pady=3)
            if combo is not None:
                w: ttk.Entry | ttk.Combobox = ttk.Combobox(parent, textvariable=self.sv[key], width=width,
                                                           values=combo[0], state=combo[1])
            else:
                w = ttk.Entry(parent, textvariable=self.sv[key], width=width, show=show)
            w.grid(row=r, column=1, sticky="w", pady=3)
            if hint:
                ttk.Label(parent, text=hint, style="Small.TLabel").grid(row=r, column=2, sticky="w", padx=(10, 0))
            self.station_entries[key] = w
            return w

        st = section("Station")
        self.channel_combo = row(st, 0, "Channel", "channel", combo=([], "normal"),
                                 hint="Folder in OPC UA, e.g. Radios")
        row(st, 1, "Name", "name", hint="Becomes the device folder, e.g. Radios.Master_LN4")
        row(st, 2, "IP address", "ip", width=18, hint="The master station's address, e.g. 192.168.1.10")

        po = section("SNMP polling")
        self.community_entry_st = row(po, 0, "Read community", "community", show="•")
        self.st_show_comm = tk.BooleanVar(value=False)
        ttk.Checkbutton(po, text="Show", variable=self.st_show_comm,
                        command=lambda: self.community_entry_st.configure(show="" if self.st_show_comm.get() else "•")
                        ).grid(row=0, column=2, sticky="w", padx=(10, 0))
        row(po, 1, "SNMP version", "version", width=6, combo=(["1", "2c"], "readonly"))
        row(po, 2, "Port", "port", width=8, hint="Default 161")
        row(po, 3, "Scan rate (seconds)", "scan_rate_s", width=8, hint="How often to read RSSI; 0.01 s to 49 days")
        row(po, 4, "Timeout (ms)", "timeout_ms", width=8)
        row(po, 5, "Retries", "retries", width=8)
        row(po, 6, "Max repetitions", "max_repetitions", width=8, hint="Rows per GETBULK request")

        sg = section("Signal")
        ttk.Checkbutton(sg, text="Warn when a remote's RSSI is below", variable=self.sb["rssi_enabled"],
                        command=self._update_station_widgets).grid(row=0, column=0, sticky="w", pady=3)
        rssi = ttk.Entry(sg, textvariable=self.sv["rssi_warning_dbm"], width=8)
        rssi.grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Label(sg, text="dBm", style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=(6, 0))
        self.station_entries["rssi_warning_dbm"] = rssi

        rt = section("Remote tags")
        row(rt, 0, "Number of RSSI tags", "remote_tags", width=8,
            hint="Remote1 … RemoteN, each with _IP, _MAC and _Online; 0 = none")
        row(rt, 1, "Name prefix", "remote_tag_prefix", width=12)
        self.btn_lock_numbers = ttk.Button(rt, text="Lock current numbers", command=self.lock_numbers)
        self.btn_lock_numbers.grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Label(rt, text="Each radio keeps its number automatically; locking writes the numbering into the "
                           "configuration so it can't change.", style="Small.TLabel", wraplength=420,
                  justify="left").grid(row=2, column=1, columnspan=2, sticky="w", padx=(10, 0), pady=(6, 0))

        tr = section("Traps")
        ttk.Checkbutton(tr, text="Also receive traps from this station", variable=self.sb["receive_traps"]
                        ).grid(row=0, column=0, sticky="w", pady=2)
        ttk.Checkbutton(tr, text="Create coldStart, warmStart, linkUp and linkDown tags",
                        variable=self.sb["auto_create_tags"]).grid(row=1, column=0, sticky="w", pady=2)

        actions = ttk.Frame(right)
        actions.pack(side="top", fill="x", pady=(4, 0))
        self.btn_station_test = ttk.Button(actions, text="Test connection", command=self.test_station)
        self.btn_station_test.pack(side="left")
        ttk.Button(actions, text="Save and restart", style="Accent.TButton",
                   command=lambda: self.save_station(restart=True)).pack(side="right")
        ttk.Button(actions, text="Save", command=self.save_station).pack(side="right", padx=(0, 6))
        ttk.Button(actions, text="Revert", command=self.revert_station).pack(side="right", padx=(0, 6))
        self.station_msg = ttk.Label(right, text="", style="Muted.TLabel", wraplength=620, justify="left")
        self.station_msg.pack(side="top", anchor="w", pady=(10, 0))
        return tab

    def _mark_station_dirty(self) -> None:
        if not self.station_loading:
            self.station_dirty = True

    def _update_station_widgets(self) -> None:
        self.station_entries["rssi_warning_dbm"].configure(state="normal" if self.sb["rssi_enabled"].get()
                                                           else "disabled")
        self.btn_remove_station.configure(state="normal" if self.station_current is not None else "disabled")
        self.btn_lock_numbers.configure(state="normal" if self.station_current is not None else "disabled")

    def _refresh_stations(self, keep: str | None = None) -> None:
        try:
            text = self.ctl.read_text()
            self.station_list = stations_mod.list_stations(text)
            channels = stations_mod.channel_names(text)
        except Exception as exc:
            self.station_list, channels = [], []
            self._station_message(f"Can't read the configuration: {exc}", error=True)
        tree = self.station_tree
        tree.delete(*tree.get_children())
        for i, stn in enumerate(self.station_list):
            tree.insert("", "end", iid=f"st{i}", values=(stn.path, stn.ip))
        self.channel_combo.configure(values=sorted(set(channels) | {stations_mod.DEFAULT_CHANNEL}))
        target = next((i for i, x in enumerate(self.station_list) if x.path == keep), None)
        if target is None and self.station_list and keep != "__new__":
            target = 0
        if target is not None:
            tree.selection_set(f"st{target}")
            self._load_station(self.station_list[target])
        else:
            self.add_station(force=True)

    def _load_station(self, stn: stations_mod.Station | None) -> None:
        self.station_loading = True
        try:
            src = stn or stations_mod.new_station(self.ctl.read_text())
            self.station_current = stn
            values = {"channel": src.channel, "name": src.name, "ip": src.ip, "community": src.community,
                      "version": src.version, "port": str(src.port), "scan_rate_s": f"{src.scan_rate_ms / 1000:g}",
                      "timeout_ms": str(src.timeout_ms), "retries": str(src.retries),
                      "max_repetitions": str(src.max_repetitions),
                      "rssi_warning_dbm": str(src.rssi_warning_dbm if src.rssi_warning_dbm is not None
                                              else stations_mod.DEFAULT_RSSI_WARNING),
                      "remote_tags": str(src.remote_tags), "remote_tag_prefix": src.remote_tag_prefix}
            for k, v in values.items():
                self.sv[k].set(v)
            self.sb["rssi_enabled"].set(src.rssi_warning_dbm is not None)
            self.sb["receive_traps"].set(src.receive_traps)
            self.sb["auto_create_tags"].set(src.auto_create_tags)
        finally:
            self.station_loading = False
        self.station_dirty = False
        self.station_title.configure(text=f"Station {stn.path}" if stn else "New station")
        self._station_message("Fill in the master station's details, then Save." if stn is None else "")
        self._update_station_widgets()

    def _station_message(self, text: str, error: bool = False) -> None:
        self.station_msg.configure(text=text, style="Error.TLabel" if error else "Muted.TLabel")

    def _confirm_discard(self) -> bool:
        if not self.station_dirty:
            return True
        name = self.station_current.path if self.station_current else "the new station"
        return bool(messagebox.askokcancel("Stations", f"Discard your changes to {name}?", parent=self.root))

    def _on_station_select(self, _event=None) -> None:
        if self.station_loading:
            return
        sel = self.station_tree.selection()
        if not sel:
            return
        stn = self.station_list[int(sel[0][2:])]
        if self.station_current is not None and stn.path == self.station_current.path and not self.station_dirty:
            return
        if not self._confirm_discard():
            return
        self._load_station(stn)

    def add_station(self, force: bool = False) -> None:
        if not force and not self._confirm_discard():
            return
        self.station_loading = True
        self.station_tree.selection_set()
        self.station_loading = False
        self._load_station(None)
        self.station_entries["ip"].focus_set()

    def revert_station(self) -> None:
        self._load_station(self.station_current)

    def _form_values(self) -> dict:
        v: dict = {k: var.get() for k, var in self.sv.items()}
        v.update({k: var.get() for k, var in self.sb.items()})
        return v

    def _editor_blocks(self) -> bool:
        if self.editor.edit_modified():
            messagebox.showinfo("Stations", "The Configuration tab has unsaved edits. Save or reload them there "
                                "first, so the two don't overwrite each other.", parent=self.root)
            return True
        return False

    def save_station(self, restart: bool = False) -> None:
        if self._editor_blocks():
            return
        text = self.ctl.read_text()
        stn, problems = stations_mod.parse_form(self._form_values(), self.station_current, text)
        if problems or stn is None:
            self._station_message("Not saved. " + " ".join(m for _, m in problems), error=True)
            if problems and problems[0][0] in self.station_entries:
                self.station_entries[problems[0][0]].focus_set()
            return
        try:
            new_text = stations_mod.save_station(text, stn, self.station_current)
            self.ctl.save_text(new_text)
        except (ValueError, OSError) as exc:
            self._station_message(f"Not saved: {exc}", error=True)
            return
        self.station_dirty = False
        self._load_config_into_ui()
        self._refresh_stations(keep=stn.path)
        if restart:
            self._station_message(f"Saved {stn.path}. Restarting the gateway…")
            if self.ctl.running:
                self.restart_pending = True
                self.stop()
            else:
                self.start()
        else:
            self._station_message(f"Saved {stn.path} to {self.ctl.config_path.name} (previous version kept as .bak)."
                                  + (" Restart the gateway to apply it." if self.ctl.running else ""))

    def lock_numbers(self) -> None:
        stn = self.station_current
        if stn is None or self._editor_blocks():
            return
        if self.station_dirty:
            self._station_message("Save or revert your changes first, then lock the numbers.", error=True)
            return
        live = next((p for p in self.ctl.snapshot().get("polling") or [] if p["path"] == stn.path), None)
        if live is None:
            self._station_message("Start the gateway and let it poll this station once, then lock the numbers.",
                                  error=True)
            return
        if not live["slots"]:
            self._station_message("No remotes have numbers yet.", error=True)
            return
        try:
            self.ctl.save_text(stations_mod.lock_numbers(self.ctl.read_text(), stn, live["slots"]))
        except (ValueError, OSError) as exc:
            self._station_message(f"Not locked: {exc}", error=True)
            return
        self._load_config_into_ui()
        self._refresh_stations(keep=stn.path)
        pairs = ", ".join(f"{live['prefix']}{n} = {m}" for n, m in sorted(live["slots"].items())[:4])
        more = " …" if len(live["slots"]) > 4 else ""
        self._station_message(f"Locked {len(live['slots'])} numbers for {stn.path} ({pairs}{more}) under "
                              f"polling.remote_slots.")

    def remove_station(self) -> None:
        stn = self.station_current
        if stn is None or self._editor_blocks():
            return
        if not messagebox.askokcancel("Remove station", f"Remove {stn.path} ({stn.ip}) from the configuration? "
                                      "Its tags and history stop updating after a restart.", parent=self.root):
            return
        try:
            self.ctl.save_text(stations_mod.delete_station(self.ctl.read_text(), stn))
        except (ValueError, OSError) as exc:
            self._station_message(f"Not removed: {exc}", error=True)
            return
        self.station_dirty = False
        self._load_config_into_ui()
        self._refresh_stations()
        self._station_message(f"Removed {stn.path}." + (" Restart the gateway to apply it." if self.ctl.running
                                                         else ""))

    def test_station(self) -> None:
        if self.station_testing:
            return
        stn, problems = stations_mod.parse_form(self._form_values(), self.station_current, self.ctl.read_text())
        problems = [p for p in problems if p[0] not in ("name", "channel")]
        if problems:
            self._station_message("Can't test yet. " + " ".join(m for _, m in problems), error=True)
            return
        v = self._form_values()
        self.station_testing = True
        self.btn_station_test.configure(state="disabled")
        self._station_message(f"Asking {v['ip']} for its remotes…")

        def work() -> None:
            import asyncio

            from .ge_orbit import read_remotes
            from .snmp_client import SnmpClient

            async def probe():
                client = SnmpClient(v["ip"].strip(), v["community"], v["version"], int(v["port"]),
                                    int(v["timeout_ms"]) / 1000, int(v["retries"]))
                try:
                    return await read_remotes(client, int(v["max_repetitions"]))
                finally:
                    client.close()
            try:
                remotes = asyncio.run(probe())
                if remotes:
                    rs = [r.rssi for r in remotes if r.rssi is not None]
                    rng = f", RSSI {max(rs)} to {min(rs)} dBm" if rs else ""
                    result = (True, f"Connected to {v['ip']}: {len(remotes)} remote radios{rng}.")
                else:
                    result = (True, f"Connected to {v['ip']}, but it reports no remote radios.")
            except Exception as exc:
                result = (False, f"No usable answer from {v['ip']}:{v['port']} ({exc}). Check the IP address and "
                                 f"read community, the master's SNMP access list, and that UDP {v['port']} is open.")
            self.ctl.events.put(("station_test", result))

        threading.Thread(target=work, name="station-test", daemon=True).start()

    def _on_station_test(self, ok: bool, message: str) -> None:
        self.station_testing = False
        self.btn_station_test.configure(state="normal")
        self._station_message(message, error=not ok)

    # ------------------------------------------------------------------ test tab
    def _build_test_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(16, 14, 16, 14))
        self.nb.add(tab, text="Send test trap")
        form = ttk.Frame(tab)
        form.pack(side="top", anchor="nw", fill="x")
        form.columnconfigure(1, weight=1)
        pad: dict[str, Any] = {"pady": 5, "sticky": "w"}

        ttk.Label(form, text="Send to").grid(row=0, column=0, padx=(0, 16), **pad)
        dest = ttk.Frame(form)
        dest.grid(row=0, column=1, **pad)
        self.t_host = tk.StringVar(value="127.0.0.1")
        self.t_port = tk.StringVar(value="162")
        ttk.Entry(dest, textvariable=self.t_host, width=22).pack(side="left")
        ttk.Label(dest, text="port").pack(side="left", padx=(10, 6))
        ttk.Entry(dest, textvariable=self.t_port, width=7).pack(side="left")

        ttk.Label(form, text="SNMP version").grid(row=1, column=0, padx=(0, 16), **pad)
        ver = ttk.Frame(form)
        ver.grid(row=1, column=1, **pad)
        self.t_version = tk.StringVar(value="2c")
        for value, label in (("1", "v1"), ("2c", "v2c"), ("3", "v3")):
            ttk.Radiobutton(ver, text=label, value=value, variable=self.t_version,
                            command=self._update_test_form).pack(side="left", padx=(0, 14))

        ttk.Label(form, text="Notification").grid(row=2, column=0, padx=(0, 16), **pad)
        oid = ttk.Frame(form)
        oid.grid(row=2, column=1, **pad)
        self.t_oid = tk.StringVar(value="linkDown")
        ttk.Entry(oid, textvariable=self.t_oid, width=40).pack(side="left")
        ttk.Label(oid, text="OID or name, such as linkDown or coldStart", style="Small.TLabel").pack(
            side="left", padx=(10, 0))

        ttk.Label(form, text="Variables").grid(row=3, column=0, padx=(0, 16), pady=5, sticky="nw")
        vbf = ttk.Frame(form)
        vbf.grid(row=3, column=1, pady=5, sticky="w")
        self.t_varbinds = tk.Text(vbf, height=4, width=52, font=self.f_mono, background=FIELD, foreground=INK,
                                  relief="flat", highlightthickness=1, highlightbackground=LINE,
                                  highlightcolor=ACCENT, padx=6, pady=4, undo=True)
        self.t_varbinds.insert("1.0", "ifIndex.3 i 3\nifDescr.3 s eth3")
        self.t_varbinds.pack(side="top", anchor="w")
        ttk.Label(vbf, text="One per line: OID TYPE VALUE. Types: i integer, u gauge, c counter, C counter64, "
                            "t timeticks, a IP address, o OID, s string, x hex, n null",
                  style="Small.TLabel", wraplength=520, justify="left").pack(side="top", anchor="w", pady=(4, 0))

        self.t_inform = tk.BooleanVar(value=False)
        self.inform_check = ttk.Checkbutton(form, text="Send as an inform and wait for the acknowledgement",
                                            variable=self.t_inform)
        self.inform_check.grid(row=4, column=1, **pad)

        self.community_label = ttk.Label(form, text="Community")
        self.community_label.grid(row=5, column=0, padx=(0, 16), **pad)
        self.t_community = tk.StringVar(value="public")
        self.community_entry = ttk.Entry(form, textvariable=self.t_community, width=22, show="•")
        self.community_entry.grid(row=5, column=1, **pad)

        self.v3_frame = ttk.Labelframe(form, text="SNMPv3 credentials", padding=(12, 8))
        self.v3_frame.grid(row=6, column=0, columnspan=2, pady=(8, 5), sticky="w")
        self.t_user = tk.StringVar(value=CUSTOM_USER)
        ttk.Label(self.v3_frame, text="User").grid(row=0, column=0, padx=(0, 12), pady=4, sticky="w")
        self.user_combo = ttk.Combobox(self.v3_frame, textvariable=self.t_user, state="readonly", width=28)
        self.user_combo.grid(row=0, column=1, pady=4, sticky="w")
        self.user_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_test_form())
        self.t_cname = tk.StringVar()
        self.t_auth = tk.StringVar(value="SHA256")
        self.t_akey = tk.StringVar()
        self.t_priv = tk.StringVar(value="AES")
        self.t_pkey = tk.StringVar()
        self.custom_rows: list[tk.Widget] = []
        rows = [("User name", ttk.Entry(self.v3_frame, textvariable=self.t_cname, width=30)),
                ("Authentication", ttk.Combobox(self.v3_frame, textvariable=self.t_auth, state="readonly", width=12,
                                                values=["NONE", *AUTH_PROTOCOLS])),
                ("Auth key", ttk.Entry(self.v3_frame, textvariable=self.t_akey, width=30, show="•")),
                ("Privacy", ttk.Combobox(self.v3_frame, textvariable=self.t_priv, state="readonly", width=12,
                                         values=["NONE", *PRIV_PROTOCOLS])),
                ("Priv key", ttk.Entry(self.v3_frame, textvariable=self.t_pkey, width=30, show="•"))]
        for r, (label, widget) in enumerate(rows, start=1):
            lab = ttk.Label(self.v3_frame, text=label)
            lab.grid(row=r, column=0, padx=(0, 12), pady=4, sticky="w")
            widget.grid(row=r, column=1, pady=4, sticky="w")
            self.custom_rows += [lab, widget]

        actions = ttk.Frame(tab)
        actions.pack(side="top", anchor="w", pady=(14, 0))
        self.btn_send = ttk.Button(actions, text="Send trap", style="Accent.TButton", command=self.send_test)
        self.btn_send.pack(side="left")
        self.test_result = ttk.Label(actions, text="", wraplength=700, justify="left")
        self.test_result.pack(side="left", padx=(14, 0))
        self._update_test_form()
        return tab

    # ------------------------------------------------------------------ config tab
    def _build_config_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Configuration")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Button(bar, text="Save and restart", style="Accent.TButton",
                   command=self.save_and_restart).pack(side="right")
        ttk.Button(bar, text="Save", command=self.save_config).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Check", command=self.validate_config).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Reload from file", command=self.reload_config).pack(side="right", padx=(0, 6))
        self.config_msg = ttk.Label(bar, text="", style="Muted.TLabel", wraplength=640, justify="left")
        self.config_msg.pack(side="left", fill="x", expand=True)
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        self.editor = self._text_box(box, height=20, readonly=False)
        self.editor.bind("<<Modified>>", self._on_editor_modified)
        return tab

    # ------------------------------------------------------------------ log tab
    def _build_log_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.nb, padding=(0, 10, 0, 0))
        self.nb.add(tab, text="Log")
        bar = ttk.Frame(tab)
        bar.pack(side="top", fill="x", pady=(0, 8))
        ttk.Label(bar, text="Gateway messages, newest at the bottom", style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="Clear log", command=self.clear_log).pack(side="right")
        box = ttk.Frame(tab)
        box.pack(side="top", fill="both", expand=True)
        self.log_text = self._text_box(box, height=20, readonly=True)
        self.log_text.tag_configure("WARNING", foreground=WARN_INK)
        self.log_text.tag_configure("ERROR", foreground=ALARM)
        self.log_text.tag_configure("CRITICAL", foreground=ALARM)
        return tab

    # ================================================================== config handling
    def _load_config_into_ui(self, first: bool = False) -> None:
        try:
            text = self.ctl.read_text()
        except OSError as exc:
            text = ""
            self._set_config_msg(f"Can't read {self.ctl.config_path}: {exc}", error=True)
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", text)
        self.editor.edit_reset()
        self.editor.edit_modified(False)
        try:
            cfg = self.ctl.load()
        except Exception as exc:
            self._set_config_msg(f"The configuration has a problem: {exc}", error=True)
            self.status_line.configure(text="Fix the configuration before starting the gateway.")
            if first:
                self.nb.select(self.tab_config)
            return
        self._refresh_from_config(cfg)
        if not first:
            self._set_config_msg("Loaded from file.")

    def _refresh_from_config(self, cfg: dict) -> None:
        """Update form defaults and hints from a loaded config (never touches the editor)."""
        devices = list(cfg.get("_devices") or [])
        if [d.path for d in devices] != [d.path for d in self.tag_devices] or \
                [len(d.tags) for d in devices] != [len(d.tags) for d in self.tag_devices]:
            self.tag_devices = devices
            self.config_tag_paths = {d.tag_path(t) for d in devices for t in d.tags}
            self._rebuild_tag_tree()
        snmp = cfg["snmp"]
        self.t_port.set(str(snmp["listen_port"]))
        if snmp.get("communities"):
            self.t_community.set(str(snmp["communities"][0]))
        names = [u.name for u in self.ctl.configured_users()]
        self.user_combo.configure(values=[*names, CUSTOM_USER])
        if names and self.t_user.get() not in names:
            self.t_user.set(names[0])
        self.empty_traps.configure(text=f"No traps yet.\nPoint your devices at this computer on UDP port "
                                        f"{snmp['listen_port']}, or use the Send test trap tab.")
        self._update_test_form()

    def _set_config_msg(self, text: str, error: bool = False) -> None:
        self.config_msg.configure(text=text, style="Error.TLabel" if error else "Muted.TLabel")

    def _on_editor_modified(self, _event=None) -> None:
        if self.editor.edit_modified():
            self._set_config_msg("Unsaved changes.")

    def _editor_text(self) -> str:
        return self.editor.get("1.0", "end-1c")

    def validate_config(self) -> bool:
        try:
            cfg = self.ctl.validate_text(self._editor_text())
        except ValueError as exc:
            self._set_config_msg(f"Not valid: {exc}", error=True)
            return False
        users = ", ".join(f"{u.name} ({u.level})" for u in cfg["snmp"]["v3"]["_users"]) or "none"
        self._set_config_msg(f"Valid. Listens on UDP {cfg['snmp']['listen_port']}, OPC UA {cfg['opcua']['mode']} "
                             f"mode, SNMPv3 users: {users}.")
        return True

    def save_config(self) -> bool:
        try:
            self.ctl.save_text(self._editor_text())
        except (ValueError, OSError) as exc:
            self._set_config_msg(f"Not saved: {exc}", error=True)
            return False
        self.editor.edit_modified(False)
        self._load_config_into_ui()
        self._set_config_msg("Saved. The previous version was kept as a .bak file."
                             + (" Restart the gateway to apply it." if self.ctl.running else ""))
        return True

    def save_and_restart(self) -> None:
        if not self.save_config():
            return
        if self.ctl.running:
            self.restart_pending = True
            self.stop()
        else:
            self.start()

    def reload_config(self) -> None:
        if self.editor.edit_modified() and not messagebox.askokcancel(
                "Reload configuration", "Discard your unsaved changes and reload the file?", parent=self.root):
            return
        self._load_config_into_ui()

    def open_config(self) -> None:
        if self.ctl.running:
            messagebox.showinfo("Open configuration", "Stop the gateway before opening another configuration.",
                                parent=self.root)
            return
        path = filedialog.askopenfilename(parent=self.root, title="Open configuration",
                                          filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*")])
        if path:
            self.ctl.config_path = Path(path)
            self.config_label.configure(text=path)
            self._load_config_into_ui()

    # ================================================================== start / stop
    def start(self) -> None:
        if self.ctl.running:
            return
        try:
            self.ctl.start()
        except Exception as exc:
            self._show_state("error", "Not started")
            self.status_line.configure(text=f"Can't start: {exc}")
            messagebox.showerror("Can't start the gateway", str(exc), parent=self.root)
            return
        self.had_error = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="disabled")
        self._show_state("busy", "Starting…")

    def stop(self) -> None:
        if not self.ctl.running:
            return
        self.btn_stop.configure(state="disabled")
        self._show_state("busy", "Stopping…")
        threading.Thread(target=self.ctl.stop, name="gateway-stop", daemon=True).start()

    def _show_state(self, state: str, text: str) -> None:
        colour = {"running": ACCENT, "error": ALARM, "busy": WARN}.get(state, STOPPED)
        self.status_dot.itemconfigure(self.dot, fill=colour)
        self.status_text.configure(text=text)

    def _on_started(self, info: dict) -> None:
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._show_state("running", "Running")
        versions = ", ".join(info.get("versions") or [])
        listen = info.get("listen") or []
        listen = ", ".join(listen) if isinstance(listen, list) else str(listen)
        self.info_listen.configure(text=f"Listening on {listen} for SNMP {versions}")
        mode = "server" if info.get("mode") == "server" else "client, writing to"
        self.info_opcua.configure(text=f"OPC UA {mode} {info.get('opcua')}")
        if self.ctl.cfg:
            self._refresh_from_config(self.ctl.cfg)
        if self.ctl.started_at:
            self.status_line.configure(text=f"Running since {self.ctl.started_at:%H:%M:%S}")

    def _on_stopped(self) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.had_error:
            self._show_state("error", "Stopped after an error")
        else:
            self._show_state("stopped", "Stopped")
            self.status_line.configure(text="Gateway stopped.")
        self.info_listen.configure(text="")
        self.info_opcua.configure(text="")
        if self.restart_pending:
            self.restart_pending = False
            self.start()

    def _on_error(self, message: str) -> None:
        self.had_error = True
        self.restart_pending = False
        self.status_line.configure(text=message)
        self.root.after_idle(lambda: messagebox.showerror("Gateway stopped", message, parent=self.root))

    # ================================================================== event pump
    def _poll(self) -> None:
        if self.polling:          # a modal dialog can run the event loop re-entrantly
            return
        self.polling = True
        try:
            for _ in range(500):
                kind, payload = self.ctl.events.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        except Exception:
            logging.getLogger("snmp2opcua.gui").exception("UI update failed")
        finally:
            self.polling = False
        self.root.after(150, self._poll)

    def _handle(self, kind: str, payload) -> None:
        if kind == "trap":
            self._add_trap(payload)
        elif kind in ("rejected", "malformed"):
            self._add_rejection(kind, payload)
        elif kind == "log":
            self._append_log(*payload)
        elif kind == "started":
            self._on_started(payload)
        elif kind == "stopped":
            self._on_stopped()
        elif kind == "error":
            self._on_error(payload)
        elif kind == "test_result":
            self._on_test_result(*payload)
        elif kind == "diag_result":
            self._on_diag_result(payload)
        elif kind == "tags":
            self._on_tags(payload)
        elif kind == "radios":
            self._on_radios(payload)
        elif kind == "station_test":
            self._on_station_test(*payload)
        elif kind == "catalog":
            self._on_catalog(payload)

    def _tick(self) -> None:
        self._live_tick()
        stats = self.ctl.stats()
        for key, (stripe, num, cap, caption) in self.tiles.items():
            value = stats.get(key)
            num.configure(text="–" if value is None else f"{value:,}")
            alert = TILE_ALERT.get(key) if value else None
            stripe.configure(background=alert or SURFACE)
            cap.configure(text=f"⚠ {caption}" if alert else caption, foreground=INK if alert else MUTED)
        self.root.after(1000, self._tick)

    # ================================================================== traps
    @staticmethod
    def _varbind_summary(d: dict) -> str:
        return ",  ".join(f"{v['name']} = {v['value']}" for v in d.get("varbinds", []))

    def _trap_values(self, d: dict) -> tuple:
        return (d["time"], d["source_ip"], d["version"], d.get("security_name", ""), d["trap_name"],
                d.get("description", ""), f"{d['severity']}  {d['severity_label']}", self._varbind_summary(d))

    @staticmethod
    def _tag_for(d: dict) -> tuple[str, ...]:
        return ("high",) if d["severity"] >= 800 else ("medium",) if d["severity"] >= 600 else ()

    def _matches(self, d: dict) -> bool:
        needle = self.filter_var.get().strip().lower()
        if not needle:
            return True
        if "_search" not in d:
            d["_search"] = " ".join(str(x) for x in self._trap_values(d)).lower() + " " + d["trap_oid"]
        return needle in d["_search"]

    def _add_trap(self, d: dict) -> None:
        self.seq += 1
        d["_iid"] = f"t{self.seq}"
        if len(self.traps) == self.traps.maxlen:
            oldest = self.traps[0]
            self.trap_by_iid.pop(oldest["_iid"], None)
            if self.trap_tree.exists(oldest["_iid"]):
                self.trap_tree.delete(oldest["_iid"])
        self.traps.append(d)
        self.trap_by_iid[d["_iid"]] = d
        self._update_device(d)
        if self.paused:
            self.unseen += 1
            self.btn_pause.configure(text=f"Resume feed ({self.unseen} new)")
        elif self._matches(d):
            self.trap_tree.insert("", 0, iid=d["_iid"], values=self._trap_values(d), tags=self._tag_for(d))
        self._update_trap_count()

    def _update_trap_count(self) -> None:
        shown = len(self.trap_tree.get_children())
        total = len(self.traps)
        self.trap_count_label.configure(text=f"Showing {shown:,} of {total:,}" if total else "")
        if total:
            self.empty_traps.place_forget()
        else:
            self.empty_traps.place(relx=0.5, rely=0.5, anchor="center")

    def _refilter(self) -> None:
        self.trap_tree.delete(*self.trap_tree.get_children())
        for d in reversed(self.traps):
            if self._matches(d):
                self.trap_tree.insert("", "end", iid=d["_iid"], values=self._trap_values(d), tags=self._tag_for(d))
        self._update_trap_count()

    def _show_trap_detail(self, _event=None) -> None:
        sel = self.trap_tree.selection()
        d = self.trap_by_iid.get(sel[0]) if sel else None
        text = "" if d is None else json.dumps({k: v for k, v in d.items() if not k.startswith("_")},
                                               indent=2, ensure_ascii=False, default=str)
        self.trap_detail.configure(state="normal")
        self.trap_detail.delete("1.0", "end")
        self.trap_detail.insert("1.0", text)
        self.trap_detail.configure(state="disabled")

    def toggle_pause(self) -> None:
        self.paused = not self.paused
        if self.paused:
            self.unseen = 0
            self.btn_pause.configure(text="Resume feed")
        else:
            self.btn_pause.configure(text="Pause feed")
            self._refilter()

    def clear_traps(self) -> None:
        self.traps.clear()
        self.trap_by_iid.clear()
        self.trap_tree.delete(*self.trap_tree.get_children())
        self._show_trap_detail()
        self._update_trap_count()

    def export_csv(self) -> None:
        rows = [d for d in reversed(self.traps) if self._matches(d)]
        if not rows:
            messagebox.showinfo("Export CSV", "There are no traps to export.", parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export traps", defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")], initialfile="traps.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["received_at", "source_ip", "version", "v3_user", "trap_oid", "trap_name",
                            "severity", "uptime", "varbinds_json"])
                for d in rows:
                    w.writerow([d["received_at"], d["source_ip"], d["version"], d.get("security_name", ""),
                                d["trap_oid"], d["trap_name"], d["severity"], d.get("uptime", ""),
                                json.dumps(d.get("varbinds", []), ensure_ascii=False, default=str)])
        except OSError as exc:
            messagebox.showerror("Export CSV", f"Couldn't write {path}: {exc}", parent=self.root)
            return
        self.status_line.configure(text=f"Exported {len(rows):,} traps to {path}")

    # ================================================================== devices / rejected / log
    def _update_device(self, d: dict) -> None:
        ip = d["source_ip"]
        dev = self.devices.setdefault(ip, {"count": 0})
        dev["count"] += 1
        values = (ip, f"{dev['count']:,}", d["trap_name"], d["time"], d["version"])
        tags = self._tag_for(d)[:1] if d["severity"] >= 800 else ()
        iid = "dev:" + ip
        if self.device_tree.exists(iid):
            self.device_tree.item(iid, values=values, tags=tags)
            self.device_tree.move(iid, "", 0)
        else:
            self.device_tree.insert("", 0, iid=iid, values=values, tags=tags)
        self.nb.tab(self.tab_devices, text=f"Sources ({len(self.devices)})")

    def _add_rejection(self, kind: str, p: dict) -> None:
        self.reject_count += 1
        label = "Rejected" if kind == "rejected" else "Unreadable packet"
        self.reject_tree.insert("", 0, values=(p.get("time", ""), p.get("source", ""), label, p.get("reason", "")))
        children = self.reject_tree.get_children()
        if len(children) > MAX_REJECTS:
            self.reject_tree.delete(*children[MAX_REJECTS:])
        self.nb.tab(self.tab_rejected, text=f"Rejected ({self.reject_count:,})")

    def _append_log(self, level: str, line: str) -> None:
        t = self.log_text
        at_bottom = t.yview()[1] >= 0.999
        t.configure(state="normal")
        t.insert("end", line + "\n", (level,))
        lines = int(t.index("end-1c").split(".")[0])
        if lines > MAX_LOG_LINES:
            t.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
        t.configure(state="disabled")
        if at_bottom:
            t.see("end")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ================================================================== diagnostics
    def _on_tab_changed(self, _event=None) -> None:
        if self.nb.select() != str(self.tab_diag) or self.diag_running:
            return
        if self.diag_when is None or (datetime.now() - self.diag_when).total_seconds() > 30:
            self.run_checks()

    def run_checks(self) -> None:
        if self.diag_running:
            return
        self.diag_running = True
        self.btn_diag.configure(state="disabled")
        self.diag_summary.configure(text="Running checks…", style="Muted.TLabel")
        tk_version = f"{tk.TkVersion}"

        def work() -> None:
            try:
                result: object = run_diagnostics(self.ctl, tk_version=tk_version)
            except Exception as exc:     # a bug here must not leave the button disabled
                result = exc
            self.ctl.events.put(("diag_result", result))

        threading.Thread(target=work, name="diagnostics", daemon=True).start()

    def _on_diag_result(self, result) -> None:
        self.diag_running = False
        self.btn_diag.configure(state="normal")
        if isinstance(result, Exception):
            self.diag_summary.configure(text=f"Checks failed to run: {result}", style="Error.TLabel")
            return
        self.diag_checks, self.diag_when = result, datetime.now()
        tree = self.diag_tree
        tree.delete(*tree.get_children())
        self.diag_by_iid.clear()
        sections: dict[str, list[Check]] = {}
        for c in result:
            sections.setdefault(c.section, []).append(c)
        n = 0
        for name, checks in sections.items():
            worst = next((st for st in ("problem", "warn") if any(c.status == st for c in checks)), "")
            sec_iid = f"sec{len(self.diag_by_iid)}_{n}"
            tree.insert("", "end", iid=sec_iid, text=name, open=True, tags=("section",),
                        values=(STATUS_LABEL[worst] if worst else "", summarize(checks)))
            for c in checks:
                n += 1
                iid = f"chk{n}"
                tree.insert(sec_iid, "end", iid=iid, text=c.name, values=(c.label, c.result),
                            tags=(c.status,) if c.status in ("problem", "warn") else ())
                self.diag_by_iid[iid] = c
        summary = summarize(result)
        problems = sum(c.status == "problem" for c in result)
        self.diag_summary.configure(text=f"{summary}. Last run {self.diag_when:%H:%M:%S}.",
                                    style="Error.TLabel" if problems else "TLabel")
        self.nb.tab(self.tab_diag, text=f"Diagnostics ({problems})" if problems else "Diagnostics")
        first_bad = next((iid for iid, c in self.diag_by_iid.items() if c.status in ("problem", "warn")), None)
        if first_bad:
            tree.selection_set(first_bad)
            tree.see(first_bad)
            self._show_diag_detail()

    def _set_diag_detail(self, parts: list[tuple[str, str]]) -> None:
        t = self.diag_detail
        t.configure(state="normal")
        t.delete("1.0", "end")
        for text, tag in parts:
            t.insert("end", text, (tag,) if tag else ())
        t.configure(state="disabled")

    def _show_diag_detail(self, _event=None) -> None:
        sel = self.diag_tree.selection()
        c = self.diag_by_iid.get(sel[0]) if sel else None
        if c is None:
            return
        parts = [(f"{c.name}  ({c.label})\n", "head"), (c.result + "\n", "")]
        if c.hint:
            parts += [("\nHow to fix\n" if c.status in ("problem", "warn") else "\nNote\n", "head"), (c.hint, "")]
        self._set_diag_detail(parts)

    def copy_report(self) -> None:
        if not self.diag_checks:
            self.diag_summary.configure(text="Run the checks first.", style="Muted.TLabel")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(report_text(self.diag_checks, self.diag_when))
        self.status_line.configure(text="Diagnostics report copied to the clipboard.")

    def save_report(self) -> None:
        if not self.diag_checks:
            self.diag_summary.configure(text="Run the checks first.", style="Muted.TLabel")
            return
        when = self.diag_when or datetime.now()
        path = filedialog.asksaveasfilename(parent=self.root, title="Save diagnostics report",
                                            defaultextension=".txt", filetypes=[("Text", "*.txt")],
                                            initialfile=f"snmp2opcua-diagnostics-{when:%Y%m%d-%H%M}.txt")
        if not path:
            return
        try:
            Path(path).write_text(report_text(self.diag_checks, when), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Save report", f"Couldn't write {path}: {exc}", parent=self.root)
            return
        self.status_line.configure(text=f"Diagnostics report saved to {path}")

    # ================================================================== test traps
    def _update_test_form(self) -> None:
        v = self.t_version.get()
        if v == "3":
            self.community_label.grid_remove()
            self.community_entry.grid_remove()
            self.v3_frame.grid()
        else:
            self.community_label.grid()
            self.community_entry.grid()
            self.v3_frame.grid_remove()
        self.inform_check.configure(state="disabled" if v == "1" else "normal")
        if v == "1":
            self.t_inform.set(False)
        custom = self.t_user.get() == CUSTOM_USER
        for w in self.custom_rows:
            if custom:
                w.grid()
            else:
                w.grid_remove()

    def _test_request(self) -> TrapRequest:
        try:
            port = int(self.t_port.get())
            if not 0 < port < 65536:
                raise ValueError
        except ValueError:
            raise ValueError("Port must be a number from 1 to 65535") from None
        varbinds = self.t_varbinds.get("1.0", "end-1c")
        parse_varbind_lines(varbinds)        # report mistakes before anything is sent
        req = TrapRequest(host=self.t_host.get().strip() or "127.0.0.1", port=port, version=self.t_version.get(),
                          trap_oid=self.t_oid.get().strip() or "linkDown", varbinds=varbinds,
                          inform=bool(self.t_inform.get()), community=self.t_community.get())
        if req.version == "3":
            name = self.t_user.get()
            if name != CUSTOM_USER:
                req.user = next((u for u in self.ctl.configured_users() if u.name == name), None)
            else:
                req.user = UsmUser.create(self.t_cname.get().strip(), self.t_auth.get(), self.t_akey.get() or None,
                                          self.t_priv.get(), self.t_pkey.get() or None)
        return req

    def send_test(self) -> None:
        if self.sending:
            return
        try:
            req = self._test_request()
        except ValueError as exc:
            self._on_test_result(False, str(exc))
            return
        self.sending = True
        self.btn_send.configure(state="disabled")
        self.test_result.configure(text="Sending…", style="Muted.TLabel")

        def work() -> None:
            try:
                result = (True, self.ctl.send_test_trap(req))
            except Exception as exc:
                result = (False, str(exc) or type(exc).__name__)
            self.ctl.events.put(("test_result", result))

        threading.Thread(target=work, name="send-test-trap", daemon=True).start()

    def _on_test_result(self, ok: bool, message: str) -> None:
        self.sending = False
        self.btn_send.configure(state="normal")
        self.test_result.configure(text=message if ok else f"Not sent: {message}",
                                   style="TLabel" if ok else "Error.TLabel")

    # ================================================================== closing
    def on_close(self) -> None:
        if self.editor.edit_modified() and not messagebox.askokcancel(
                "Close", "You have unsaved configuration changes. Close anyway?", parent=self.root):
            return
        if self.ctl.running:
            self.status_text.configure(text="Stopping…")
            self.root.update_idletasks()
            self.ctl.stop(timeout=8)
        self.ctl.close()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua.gui", description="Desktop window for the SNMP trap gateway")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to YAML config (default: config.yaml)")
    ap.add_argument("--start", action="store_true", help="start the gateway when the window opens")
    args = ap.parse_args(argv)
    if tk is None:
        print("Tkinter is not available in this Python installation.\n"
              "  Windows/macOS: install Python from python.org (Tkinter is included)\n"
              "  Debian/Ubuntu: sudo apt install python3-tk\n"
              "  Fedora/RHEL:   sudo dnf install python3-tkinter", file=sys.stderr)
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if sys.platform == "win32":   # crisp text on high-DPI screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    root.title("SNMP to OPC UA gateway")
    root.geometry("1200x780")
    root.minsize(920, 600)
    GatewayApp(root, GatewayController(args.config), autostart=args.start)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
