"""Modern desktop UI for the AI network scanner.

Run with:  python app.py
Optional:  python app.py 192.168.1.10   (prefills the target and starts)
"""

import ctypes
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

import scanner

# ==========================================
# THEME
# ==========================================

BG = "#0b1220"
CARD = "#141c2f"
CARD_HI = "#1b2540"
LINE = "#26324a"
TEXT = "#e8eefc"
MUTED = "#8b9bb4"
ACCENT = "#3b82f6"
ACCENT_HI = "#60a5fa"
GREEN = "#22c55e"
ORANGE = "#f59e0b"
RED = "#ef4444"
RING = "#1f2b45"

RISK_COLOR = {"SAFE": GREEN, "MEDIUM": ORANGE, "RISK": RED}
RISK_SCORE = {"SAFE": 28, "MEDIUM": 62, "RISK": 90}
RISK_BLURB = {
    "SAFE": "Low exposure",
    "MEDIUM": "Needs review",
    "RISK": "Act now",
}

FONT = "Segoe UI"


def enable_dpi_awareness():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


# ==========================================
# WIDGETS
# ==========================================

class RiskGauge(tk.Canvas):
    """Circular risk indicator: green / orange / red."""

    def __init__(self, master, size=320):
        super().__init__(master, width=size, height=size, bg=CARD,
                         highlightthickness=0, bd=0)
        self.size = size
        self.target = 0.0
        self.current = 0.0

        c = size / 2
        r = size * 0.36
        box = (c - r, c - r, c + r, c + r)

        self.create_arc(*box, start=90, extent=-359.9, style="arc",
                        outline=RING, width=16)
        self.arc = self.create_arc(*box, start=90, extent=-1, style="arc",
                                   outline=ACCENT, width=16, state="hidden")

        self.title = self.create_text(c, c - 16, text="—", fill=MUTED,
                                      font=(FONT, 26, "bold"))
        self.subtitle = self.create_text(c, c + 20, text="RISK LEVEL",
                                         fill=MUTED, font=(FONT, 8, "bold"))
        self.score = self.create_text(c, c + 44, text="", fill=MUTED,
                                      font=(FONT, 9))

    def set_risk(self, level, score):
        color = RISK_COLOR.get(level, MUTED)
        text = level if level in RISK_COLOR else "—"

        self.itemconfig(self.arc, state="normal", outline=color)
        self.itemconfig(self.title, text=text, fill=color)
        self.itemconfig(self.subtitle, text=RISK_BLURB.get(level, "RISK LEVEL"),
                        fill=MUTED)
        self.itemconfig(self.score, text=f"{score} / 100", fill=MUTED)

        self.target = max(0.0, min(100.0, score))
        # Draw the final sweep directly. Animating the arc left stale pixels on
        # some Windows builds, so the gauge is painted in one clean pass.
        self.current = self.target
        self.itemconfig(self.arc, extent=-max(0.1, self.current * 3.599))

    def reset(self):
        self.itemconfig(self.arc, state="hidden")
        self.itemconfig(self.title, text="—", fill=MUTED)
        self.itemconfig(self.subtitle, text="RISK LEVEL", fill=MUTED)
        self.itemconfig(self.score, text="", fill=MUTED)
        self.current = 0.0
        self.target = 0.0

    def _animate(self):
        if abs(self.target - self.current) < 0.5:
            self.current = self.target
            self.itemconfig(self.arc, extent=-max(0.1, self.current * 3.599))
            return

        self.current += (self.target - self.current) * 0.18
        self.itemconfig(self.arc, extent=-max(0.1, self.current * 3.599))
        self.after(16, self._animate)


def make_card(parent):
    frame = tk.Frame(parent, bg=CARD, highlightbackground=LINE,
                     highlightthickness=1, bd=0)
    return frame


def card_title(parent, text, anchor="w"):
    return tk.Label(parent, text=text, bg=CARD, fg=MUTED,
                    font=(FONT, 9, "bold"), anchor=anchor)


def accent_button(parent, text, command, width=None):
    btn = tk.Button(
        parent, text=text, command=command, bg=ACCENT, fg="#ffffff",
        activebackground=ACCENT_HI, activeforeground="#ffffff",
        relief="flat", bd=0, cursor="hand2", font=(FONT, 10, "bold"),
        padx=18, pady=8,
    )
    if width:
        btn.configure(width=width)
    btn.bind("<Enter>", lambda e: btn.configure(bg=ACCENT_HI))
    btn.bind("<Leave>", lambda e: btn.configure(bg=ACCENT))
    return btn


def ghost_button(parent, text, command):
    btn = tk.Button(
        parent, text=text, command=command, bg=CARD_HI, fg=TEXT,
        activebackground=LINE, activeforeground=TEXT, relief="flat", bd=0,
        cursor="hand2", font=(FONT, 9), padx=12, pady=6,
    )
    return btn


# ==========================================
# APP
# ==========================================

class App:
    def __init__(self, root, initial_target=""):
        self.root = root
        self.scanning = False
        self.last_result = None

        # Tkinter must only be touched from the main thread, so worker threads
        # hand their updates over through this queue.
        self.queue = queue.Queue()

        root.title("AI Network Scanner")
        root.configure(bg=BG)
        root.geometry("1180x880")
        root.minsize(1040, 760)

        self._build_header()
        self._build_body()
        self._build_footer()

        self._style_tree()
        self._drain_queue()

        if initial_target:
            self.target_var.set(initial_target)
            root.after(400, self.start_scan)

    # ---------- layout ----------

    def _build_header(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 6))

        left = tk.Frame(header, bg=BG)
        left.pack(side="left")

        tk.Label(left, text="AI Network Scanner", bg=BG, fg=TEXT,
                 font=(FONT, 21, "bold")).pack(anchor="w")

        tk.Label(
            left,
            text="Nmap discovery  ·  AI risk briefing",
            bg=BG, fg=MUTED, font=(FONT, 10),
        ).pack(anchor="w", pady=(2, 0))

        self.pill = tk.Label(
            header, text="IDLE", bg=CARD, fg=MUTED, font=(FONT, 9, "bold"),
            padx=14, pady=6,
        )
        self.pill.pack(side="right", pady=6)

    def _build_body(self):
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=28, pady=10)
        body.columnconfigure(0, weight=3, minsize=560)
        body.columnconfigure(1, weight=2, minsize=380)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # --- target card ---
        target_card = make_card(left)
        target_card.grid(row=0, column=0, sticky="ew", pady=(0, 14))

        inner = tk.Frame(target_card, bg=CARD)
        inner.pack(fill="x", padx=18, pady=16)

        card_title(inner, "TARGET").pack(anchor="w")

        row = tk.Frame(inner, bg=CARD)
        row.pack(fill="x", pady=(8, 0))

        self.target_var = tk.StringVar(value="127.0.0.1")
        entry = tk.Entry(
            row, textvariable=self.target_var, bg=CARD_HI, fg=TEXT,
            insertbackground=TEXT, relief="flat", font=(FONT, 12),
            highlightthickness=1, highlightbackground=LINE,
            highlightcolor=ACCENT,
        )
        entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 10))
        entry.bind("<Return>", lambda e: self.start_scan())
        self.entry = entry

        self.scan_btn = accent_button(row, "Scan", self.start_scan)
        self.scan_btn.pack(side="left")

        self.hint = tk.Label(
            inner, text="localhost or a private IP address only",
            bg=CARD, fg=MUTED, font=(FONT, 8),
        )
        self.hint.pack(anchor="w", pady=(8, 0))

        # --- ports card ---
        ports_card = make_card(left)
        ports_card.grid(row=1, column=0, sticky="nsew")

        head = tk.Frame(ports_card, bg=CARD)
        head.pack(fill="x", padx=18, pady=(16, 8))
        card_title(head, "OPEN PORTS").pack(side="left")
        self.port_count = tk.Label(head, text="0 found", bg=CARD, fg=MUTED,
                                   font=(FONT, 9))
        self.port_count.pack(side="right")

        tree_wrap = tk.Frame(ports_card, bg=CARD)
        tree_wrap.pack(fill="both", expand=True, padx=18, pady=(0, 16))

        columns = ("port", "service", "product", "state")
        self.tree = ttk.Treeview(tree_wrap, columns=columns, show="headings",
                                 selectmode="browse")
        headings = {
            "port": ("PORT", 70),
            "service": ("SERVICE", 130),
            "product": ("PRODUCT / VERSION", 240),
            "state": ("STATE", 80),
        }
        for key, (label, width) in headings.items():
            self.tree.heading(key, text=label, anchor="w")
            self.tree.column(key, width=width, anchor="w", stretch=(key == "product"))

        scroll = ttk.Scrollbar(tree_wrap, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # --- gauge card ---
        gauge_card = make_card(right)
        gauge_card.grid(row=0, column=0, sticky="ew", pady=(0, 14))

        gwrap = tk.Frame(gauge_card, bg=CARD)
        gwrap.pack(fill="x", padx=18, pady=18)

        card_title(gwrap, "THREAT LEVEL").pack(anchor="w")

        self.gauge = RiskGauge(gwrap, size=300)
        self.gauge.pack(pady=(2, 4))

        self.target_label = tk.Label(gwrap, text="no scan yet", bg=CARD,
                                     fg=MUTED, font=(FONT, 9))
        self.target_label.pack()

        legend = tk.Frame(gwrap, bg=CARD)
        legend.pack(pady=(12, 0))
        for level, color in (("SAFE", GREEN), ("MEDIUM", ORANGE), ("RISK", RED)):
            item = tk.Frame(legend, bg=CARD)
            item.pack(side="left", padx=10)
            dot = tk.Canvas(item, width=10, height=10, bg=CARD,
                            highlightthickness=0)
            dot.create_oval(1, 1, 9, 9, fill=color, outline="")
            dot.pack(side="left")
            tk.Label(item, text=level, bg=CARD, fg=MUTED,
                     font=(FONT, 8, "bold")).pack(side="left", padx=(5, 0))

        # --- findings card ---
        findings_card = make_card(right)
        findings_card.grid(row=1, column=0, sticky="nsew")

        fhead = tk.Frame(findings_card, bg=CARD)
        fhead.pack(fill="x", padx=18, pady=(16, 6))
        card_title(fhead, "AI FINDINGS").pack(side="left")
        self.copy_btn = ghost_button(fhead, "Copy", self.copy_report)
        self.copy_btn.pack(side="right")

        self.findings = tk.Text(
            findings_card, bg=CARD, fg=TEXT, relief="flat", bd=0,
            font=(FONT, 10), wrap="word", padx=18, pady=0,
            insertbackground=TEXT, spacing1=2, spacing3=6,
        )
        self.findings.pack(fill="both", expand=True, pady=(0, 16))
        self.findings.tag_configure("muted", foreground=MUTED)
        self.findings.tag_configure("head", foreground=ACCENT_HI,
                                    font=(FONT, 9, "bold"))
        self.findings.insert("1.0", "Run a scan to get a short risk briefing.",
                             "muted")
        self.findings.configure(state="disabled")

    def _build_footer(self):
        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill="x", padx=28, pady=(0, 16))

        self.status = tk.Label(footer, text="Ready", bg=BG, fg=MUTED,
                               font=(FONT, 9), anchor="w")
        self.status.pack(side="left")

        tk.Label(footer, text="Authorized use only", bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(side="right")

        self.progress = ttk.Progressbar(footer, mode="indeterminate",
                                        length=180, style="Scan.Horizontal.TProgressbar")
        self.progress.pack(side="right", padx=12)
        self.progress.pack_forget()

    def _style_tree(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("Treeview", background=CARD, fieldbackground=CARD,
                        foreground=TEXT, rowheight=30, borderwidth=0,
                        font=(FONT, 10))
        style.configure("Treeview.Heading", background=CARD, foreground=MUTED,
                        relief="flat", borderwidth=0,
                        font=(FONT, 8, "bold"))
        style.map("Treeview.Heading", background=[("active", CARD)])
        style.map("Treeview", background=[("selected", "#1e3a8a")],
                  foreground=[("selected", "#ffffff")])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        style.configure("Scan.Horizontal.TProgressbar", troughcolor=BG,
                        background=ACCENT, borderwidth=0, thickness=6)

        style.configure("Vertical.TScrollbar", background=CARD_HI,
                        troughcolor=CARD, bordercolor=CARD, arrowcolor=MUTED,
                        borderwidth=0)

    # ---------- actions ----------

    def _call(self, fn):
        """Queue a UI update from any thread."""
        self.queue.put(fn)

    def _drain_queue(self):
        while True:
            try:
                fn = self.queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception:
                pass
        self.root.after(60, self._drain_queue)

    def set_status(self, text, color=MUTED):
        """Thread-safe: queue the update for the main thread."""
        self._call(lambda: self._apply_status(text, color))

    def set_pill(self, text, color=MUTED):
        self._call(lambda: self._apply_pill(text, color))

    def _apply_status(self, text, color=MUTED):
        self.status.configure(text=text, fg=color)

    def _apply_pill(self, text, color=MUTED):
        self.pill.configure(text=text, fg=color)

    def start_scan(self):
        if self.scanning:
            return

        try:
            target = scanner.get_target(self.target_var.get())
        except ValueError as error:
            self.hint.configure(text=str(error), fg=RED)
            return

        self.target_var.set(target)
        self.hint.configure(text="localhost or a private IP address only",
                            fg=MUTED)

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…",
                                bg=CARD_HI, fg=MUTED)
        self.progress.pack(side="right", padx=12)
        self.progress.start(12)
        self._apply_pill("SCANNING", ORANGE)
        self._apply_status(f"Scanning {target} …")
        self.gauge.reset()
        self.target_label.configure(text=target)
        self._clear_tree()
        self._set_findings("Scanning and analyzing…", muted=True)

        threading.Thread(target=self._worker, args=(target,), daemon=True).start()

    def _worker(self, target):
        started = time.time()

        try:
            self.set_status(f"Running Nmap against {target} …")
            scan = scanner.scan_ports(target)

            if scan.get("incomplete"):
                self._call(lambda: self._fail(
                    "No usable response from the host — the scan is "
                    "incomplete, not clean. It may be rate-limiting or "
                    "filtering probes. Try again in a minute."))
                return

            self._call(lambda: self._render_ports(scan))

            if not scan["ports"]:
                self._call(lambda: self._finish(
                    scan, {"risk": "SAFE", "model": "nmap",
                           "body": "No open ports found in the top 100.",
                           "error": None},
                    time.time() - started))
                return

            result = scanner.analyze(scan, on_status=self.set_status)
            self._call(lambda: self._finish(
                scan, result, time.time() - started))

        except Exception as error:  # noqa: BLE001 - show any failure in the UI
            message = str(error)
            self._call(lambda: self._fail(message))

    def _render_ports(self, scan):
        self._clear_tree()

        for item in scan["ports"]:
            product = " ".join(
                part for part in (item["product"], item["version"]) if part
            )
            tag = "hot" if item["port"] in scanner.SENSITIVE_PORTS else ""

            self.tree.insert(
                "", "end",
                values=(item["port"], item["service"], product or "—",
                        item["state"]),
                tags=(tag,),
            )

        self.tree.tag_configure("hot", foreground="#f87171")

        count = len(scan["ports"])
        self.port_count.configure(text=f"{count} found")

        if count == 0:
            self.port_count.configure(text="none open")

    def _finish(self, scan, result, elapsed):
        level = result.get("risk", "MEDIUM")
        score = RISK_SCORE.get(level, 50)

        self.gauge.set_risk(level, score)
        self.target_label.configure(text=f"{scan['host']}  ·  {elapsed:.1f}s")

        self._set_findings(result.get("body", ""), risk=level)
        self._stop_scanning()
        self._apply_pill(level, RISK_COLOR.get(level, MUTED))
        self._apply_status(
            f"Done in {elapsed:.1f}s  ·  {len(scan['ports'])} ports  ·  {level}",
            RISK_COLOR.get(level, MUTED),
        )
        self.last_result = {"scan": scan, "result": result, "elapsed": elapsed}

    def _fail(self, message):
        self._stop_scanning()
        self._apply_pill("ERROR", RED)
        self._apply_status(message, RED)
        self._set_findings(f"Scan failed:\n{message}", risk=None)

    def _stop_scanning(self):
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Scan", bg=ACCENT, fg="#ffffff")
        self.progress.stop()
        self.progress.pack_forget()

    def _clear_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _set_findings(self, body, risk=None, muted=False):
        widget = self.findings
        widget.configure(state="normal")
        widget.delete("1.0", "end")

        if muted:
            widget.insert("1.0", body, "muted")
        else:
            for line in str(body).splitlines():
                stripped = line.strip()
                if not stripped:
                    widget.insert("end", "\n")
                elif stripped.upper().rstrip(":") in ("FINDINGS", "ACTIONS"):
                    widget.insert("end", stripped.upper().rstrip(":") + "\n", "head")
                elif stripped.startswith(("-", "*", "•")):
                    widget.insert("end", "•  " + stripped.lstrip("-*• ").strip() + "\n")
                else:
                    widget.insert("end", stripped + "\n")

        widget.configure(state="disabled")

    def copy_report(self):
        if not self.last_result:
            return

        scan = self.last_result["scan"]
        result = self.last_result["result"]
        lines = [
            f"Target: {scan['host']}",
            f"Risk: {result.get('risk')}",
            f"Open ports: {len(scan['ports'])}",
            "",
            result.get("body", ""),
        ]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.set_status("Report copied to clipboard", ACCENT_HI)
        self.copy_btn.configure(text="Copied")
        self.root.after(1500, lambda: self.copy_btn.configure(text="Copy"))


def main():
    enable_dpi_awareness()
    root = tk.Tk()
    initial = sys.argv[1] if len(sys.argv) > 1 else ""
    App(root, initial_target=initial)
    root.mainloop()


if __name__ == "__main__":
    main()
