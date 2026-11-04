"""Check that an incomplete scan is reported as an error, never as SAFE."""

import tkinter as tk

import app
import scanner

root = tk.Tk()
root.withdraw()
ui = app.App(root)
root.update_idletasks()

original = scanner.scan_ports
scanner.scan_ports = lambda target: {
    "host": target, "state": "unknown", "ports": [], "incomplete": True
}

ui._worker("scanme.nmap.org")   # runs synchronously in this thread
ui._drain_queue()

pill = ui.pill.cget("text")
status = ui.status.cget("text")
arc = ui.gauge.itemcget(ui.gauge.arc, "state")
findings = ui.findings.get("1.0", "end").strip()

checks = [
    ("pill is ERROR", pill == "ERROR"),
    ("gauge shows no rating", arc == "hidden"),
    ("status explains", "incomplete" in status.lower()),
    ("findings explain", "incomplete" in findings.lower()),
    ("scan button re-enabled", str(ui.scan_btn.cget("text")) == "Scan"),
]

for label, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {label}")

scanner.scan_ports = original
root.destroy()

passed = sum(1 for _, ok in checks if ok)
print("-" * 40)
print(f"{passed}/{len(checks)} checks passed")
raise SystemExit(0 if passed == len(checks) else 1)
