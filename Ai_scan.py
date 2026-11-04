
"""AI Network Security Scanner - command line interface.

For the desktop UI run:  python app.py
"""

import sys

import scanner


def main():
    print("=" * 55)
    print("       AI NETWORK SECURITY SCANNER")
    print("=" * 55)
    print(
        "\nUse this tool only on systems you own "
        "or have explicit permission to scan."
    )

    if len(sys.argv) > 1:
        target_input = sys.argv[1]
        print(f"\nTarget taken from command line: {target_input}")
    else:
        target_input = input("\nEnter localhost or a private IP address: ")

    try:
        target = scanner.get_target(target_input)
    except ValueError as error:
        print(f"\n[!] {error}")
        return

    try:
        print(f"\n[*] Starting Nmap scan for {target}...")
        print("[*] Scanning the top 100 TCP ports. Please wait.\n")

        scan = scanner.scan_ports(target)

        print("=" * 55)
        print("RAW NMAP SCAN RESULTS")
        print("=" * 55)
        print(scanner.format_results(scan))

        if scan.get("incomplete"):
            print(
                "\n[!] The host never returned a usable answer, so this is an "
                "incomplete scan — not a clean one.\n"
                "    It may be rate-limiting or filtering probes. "
                "Try again in a minute."
            )
            return

        print("\n[*] Sending scan results to Gemini for analysis...\n")

        result = scanner.analyze(
            scan,
            on_status=lambda message: print(f"[!] {message}"),
        )

        print("\n" + "=" * 55)
        print("SECURITY BRIEF")
        print("=" * 55)
        print(f"RISK: {result['risk']}    (model: {result['model']})")
        print()
        print(result["body"])

        print("\n[*] Scan and analysis process completed.")

    except Exception as error:  # noqa: BLE001 - simple CLI error surface
        print(f"\n[!] Unexpected error: {error}")
        print("Make sure Nmap is installed and available in PATH.")


if __name__ == "__main__":
    main()
