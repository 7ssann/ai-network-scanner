"""Core engine: target validation, Nmap scanning, and brief AI analysis.

Both the CLI (Ai_scan.py) and the desktop UI (app.py) import from here so the
logic lives in exactly one place.
"""

import ipaddress
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import nmap
from google import genai
from google.genai import errors, types

# ==========================================
# CONFIGURATION
# ==========================================

# Read from the environment so no key is ever committed to Git.
#   PowerShell (current session):  $env:GEMINI_API_KEY = "your-key"
#   PowerShell (permanent):        setx GEMINI_API_KEY "your-key"
API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()

MODEL_CANDIDATES = [
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-flash-latest",
]

RETRY_ROUNDS = 1
RETRY_DELAY = 2

# Per-request timeout. The SDK retries 5xx responses internally by default,
# which can stall the UI for minutes, so retries are disabled here and handled
# by our own small loop instead.
REQUEST_TIMEOUT_MS = 45000

# Hard ceiling for a single host, so a silent or rate-limited target cannot
# block the scan indefinitely.
HOST_TIMEOUT_S = 120

# Transport-level failures worth trying on the next model.
RETRYABLE_CODES = (429, 500, 502, 503, 504)

# "en" or "ar" - language of the AI findings.
OUTPUT_LANGUAGE = "en"

RISK_LEVELS = ("SAFE", "MEDIUM", "RISK")

# Ports that deserve extra attention when shown in the UI.
SENSITIVE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 135: "rpc",
    139: "netbios", 445: "smb", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 27017: "mongo",
}


# ==========================================
# TARGET VALIDATION
# ==========================================

# Hostnames whose owner explicitly authorizes public testing.
# scanme.nmap.org is the test host published by the Nmap project itself:
# https://nmap.org/book/man.html - "you are authorized to scan scanme.nmap.org"
ALLOWED_PUBLIC_HOSTS = {"scanme.nmap.org"}


def get_target(value):
    """Normalize and validate a target. Only loopback/private hosts allowed."""
    value = (value or "").strip()

    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/")[0].split(":")[0]

    if not value:
        raise ValueError("Invalid target.")

    if value.lower() in ALLOWED_PUBLIC_HOSTS:
        return value.lower()

    try:
        ip = ipaddress.ip_address(value)

        if not (ip.is_loopback or ip.is_private):
            raise ValueError(
                "For this demo, use localhost or a private IP address."
            )

        return str(ip)

    except ValueError as error:
        if "For this demo" in str(error):
            raise

    if value.lower() in ("localhost",):
        return value

    raise ValueError(
        "For this demo, enter localhost or a private IP address, "
        "such as 127.0.0.1 or 192.168.1.10."
    )


# ==========================================
# NMAP SCAN
# ==========================================

def scan_ports(target, timeout_note=None):
    """Run the Nmap scan and return {'host', 'state', 'ports': [...], ...}."""
    scanner = nmap.PortScanner()
    # --max-retries and --host-timeout keep a slow or rate-limited host from
    # stalling the UI forever.
    started = time.time()
    scanner.scan(
        hosts=target,
        arguments=f"-sV -T4 --top-ports 100 --max-retries 2 "
                  f"--host-timeout {HOST_TIMEOUT_S}s",
    )
    elapsed = time.time() - started

    ports = []
    state = "unknown"

    hosts = scanner.all_hosts()

    # No host block at all means Nmap never got a usable answer (timeout,
    # rate limiting, or a hard filter). That is NOT the same as "no open
    # ports", so it is reported explicitly instead of a clean result.
    if not hosts:
        return {"host": target, "state": "unknown", "ports": [],
                "incomplete": True}

    for host in hosts:
        state = scanner[host].state()

        for protocol in scanner[host].all_protocols():
            for port in sorted(scanner[host][protocol].keys()):
                service = scanner[host][protocol][port]
                ports.append({
                    "port": port,
                    "proto": protocol.upper(),
                    "state": service.get("state", "unknown"),
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                })

    # Nmap writes a host block even when it gives up, so a scan that ran into
    # the host timeout but produced no port data is incomplete, not clean.
    cut_short = elapsed >= (HOST_TIMEOUT_S - 10)

    return {"host": target, "state": state, "ports": ports,
            "incomplete": bool(cut_short and not ports),
            "elapsed": elapsed}


def format_results(scan):
    """Flat text used both for the prompt and the CLI output."""
    lines = [f"Host: {scan['host']}", f"Status: {scan['state']}"]

    for item in scan["ports"]:
        lines.append(
            f"Protocol: {item['proto']} | "
            f"Port: {item['port']} | "
            f"State: {item['state']} | "
            f"Service: {item['service']} | "
            f"Product: {item['product']} | "
            f"Version: {item['version']}"
        )

    if not scan["ports"]:
        return "No open ports were returned by the scan."

    return "\n".join(lines)


# ==========================================
# GEMINI ANALYSIS (brief by design)
# ==========================================

LANG_NOTE = {
    "en": "Write in English.",
    "ar": "Write in Arabic.",
}


def build_prompt(scan_text, language=None):
    language = language or OUTPUT_LANGUAGE
    return f"""You are a network security analyst. Be extremely concise.

Return ONLY the block below. No preamble, no summary paragraph, no tables,
no markdown headings.

RISK: <SAFE|MEDIUM|RISK>
FINDINGS:
- <max 10 words>
- <max 10 words>
ACTIONS:
- <max 10 words>
- <max 10 words>

Rules:
- 2 to 4 FINDINGS and 2 to 4 ACTIONS lines.
- Only claims supported by the scan data. An open port is not a vulnerability.
- Never invent CVE IDs, versions, patch levels, or dates.
- Use SAFE only when no risky service is exposed, RISK when a clearly
  dangerous service is exposed to untrusted networks.
- {LANG_NOTE.get(language, LANG_NOTE["en"])}

Scan data:
{scan_text}
"""


def _extract_risk(text):
    match = re.search(r"RISK:\s*(SAFE|MEDIUM|RISK)\b", text or "", re.I)
    if match:
        return match.group(1).upper()

    upper = (text or "").upper()
    for level in ("RISK", "MEDIUM", "SAFE"):
        if re.search(rf"\b{level}\b", upper):
            return level

    return None


def _strip_risk_line(text):
    return re.sub(r"^\s*RISK:\s*(SAFE|MEDIUM|RISK)\s*$", "", text or "",
                  flags=re.I | re.M).strip()


def heuristic_risk(scan):
    """Fallback rating when the AI is unavailable."""
    open_ports = [p for p in scan["ports"] if p["state"] == "open"]

    if not open_ports:
        return "SAFE"

    sensitive = [p for p in open_ports if p["port"] in SENSITIVE_PORTS]

    if len(sensitive) >= 3 or len(open_ports) > 6:
        return "RISK"
    if sensitive or len(open_ports) > 2:
        return "MEDIUM"

    return "SAFE"


def analyze(scan, language=None, on_status=None):
    """Return {'risk', 'body', 'model', 'error'}.

    `on_status` is an optional callback used by the GUI to show progress.
    """
    def status(message):
        if on_status:
            on_status(message)

    scan_text = format_results(scan)

    if not API_KEY:
        return {
            "risk": heuristic_risk(scan),
            "body": "GEMINI_API_KEY is not set.\nShowing a heuristic rating only.",
            "model": "heuristic",
            "error": "missing key",
        }

    try:
        client = genai.Client(
            api_key=API_KEY,
            http_options=types.HttpOptions(
                timeout=REQUEST_TIMEOUT_MS,
                retry_options=types.HttpRetryOptions(attempts=1),
            ),
        )
    except Exception:
        client = genai.Client(api_key=API_KEY)

    prompt = build_prompt(scan_text, language)
    last_error = "unknown error"

    def attempt(model):
        """Run one model call; returns (model, text) or raises."""
        response = client.models.generate_content(model=model, contents=prompt)
        return model, (response.text or "")

    for round_number in range(RETRY_ROUNDS + 1):
        if round_number > 0:
            delay = RETRY_DELAY * round_number
            status(f"Retrying in {delay}s (pass {round_number + 1})")
            time.sleep(delay)

        # Race the models instead of trying them one by one: the first usable
        # answer wins, so a slow or overloaded model no longer stalls the UI.
        status("Analyzing with " + ", ".join(MODEL_CANDIDATES))
        pool = ThreadPoolExecutor(max_workers=len(MODEL_CANDIDATES))
        futures = {pool.submit(attempt, model): model for model in MODEL_CANDIDATES}

        try:
            for future in as_completed(futures):
                model = futures[future]
                try:
                    model_name, text = future.result()
                except errors.APIError as error:
                    last_error = f"{model}: {error.code} {error.status}"
                    status(last_error)
                    continue
                except Exception as error:  # noqa: BLE001 - surface any error
                    last_error = f"{model}: {error}"
                    status(last_error)
                    continue

                if text:
                    pool.shutdown(wait=False, cancel_futures=True)
                    return {
                        "risk": _extract_risk(text) or heuristic_risk(scan),
                        "body": _strip_risk_line(text),
                        "model": model_name,
                        "error": None,
                    }

                last_error = f"{model} returned an empty response."
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    return {
        "risk": heuristic_risk(scan),
        "body": (
            "AI analysis is unavailable right now.\n"
            f"Last error: {last_error}\n"
            "The rating below comes from the scan data only."
        ),
        "model": "heuristic",
        "error": last_error,
    }
