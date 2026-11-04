"""Headless checks for the UI logic (no window is shown)."""

import tkinter as tk

import app

root = tk.Tk()
root.withdraw()

ui = app.App(root)
root.update_idletasks()

scan = {
    "host": "scanme.nmap.org",
    "state": "up",
    "ports": [
        {"port": 22, "proto": "TCP", "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "6.6.1p1"},
        {"port": 80, "proto": "TCP", "state": "open", "service": "http",
         "product": "Apache httpd", "version": "2.4.7"},
        {"port": 9929, "proto": "TCP", "state": "open", "service": "nping-echo",
         "product": "", "version": ""},
    ],
}

results = []


def check(label, got, want):
    ok = got == want
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {label}: {got!r} (expected {want!r})")


# --- idle state ---
check("gauge idle hidden", ui.gauge.itemcget(ui.gauge.arc, "state"), "hidden")

# --- populated + finished ---
ui._render_ports(scan)
body = "FINDINGS:\n- SSH open on 22\n- HTTP open on 80\nACTIONS:\n- Restrict SSH"
ui._finish(scan, {"risk": "MEDIUM", "body": body, "model": "test",
                  "error": None}, 12.3)
root.update_idletasks()

check("gauge arc visible", ui.gauge.itemcget(ui.gauge.arc, "state"), "normal")
check("gauge colour", ui.gauge.itemcget(ui.gauge.arc, "outline"), app.ORANGE)
check("gauge sweep", round(abs(float(ui.gauge.itemcget(ui.gauge.arc, "extent"))), 1), 223.1)
check("pill", ui.pill.cget("text"), "MEDIUM")
check("port rows", len(ui.tree.get_children()), 3)
check("port count label", ui.port_count.cget("text"), "3 found")

text = ui.findings.get("1.0", "end")
check("findings has bullets", text.count("•"), 3)
check("findings has section", "FINDINGS" in text, True)
check("findings no markdown header", "##" in text, False)

check("status mentions level", "MEDIUM" in ui.status.cget("text"), True)
check("scan button reset", str(ui.scan_btn.cget("text")), "Scan")

# --- risk colour mapping ---
for level, colour in (("SAFE", app.GREEN), ("RISK", app.RED)):
    ui.gauge.set_risk(level, app.RISK_SCORE[level])
    root.update_idletasks()
    check(f"colour for {level}", ui.gauge.itemcget(ui.gauge.arc, "outline"), colour)

# --- reset clears ---
ui.gauge.reset()
root.update_idletasks()
check("reset hides arc", ui.gauge.itemcget(ui.gauge.arc, "state"), "hidden")
check("reset clears title", ui.gauge.itemcget(ui.gauge.title, "text"), "—")

# --- target validation ---
for value, expected in (("127.0.0.1", "127.0.0.1"),
                        ("scanme.nmap.org", "scanme.nmap.org"),
                        ("192.168.1.10", "192.168.1.10")):
    check(f"target {value}", app.scanner.get_target(value), expected)

root.destroy()

print("-" * 40)
print(f"{sum(results)}/{len(results)} checks passed")
raise SystemExit(0 if all(results) else 1)
