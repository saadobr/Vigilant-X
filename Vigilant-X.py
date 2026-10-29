import re
import sys
import time
import json
import csv
import os
import ipaddress
import argparse
import requests
import subprocess
from collections import Counter
from colorama import init, Fore, Style

init(autoreset=True)

def render_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                     V I G I L A N T - X                       ║
    ║        Autonomous Threat Intelligence & Log Forensics         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    print(Fore.YELLOW + "  [!] Engine Mode : Production Defensive Parser (Native Iptables Defense)")
    print(Fore.GREEN + "  [+] Lead Operator : s4yem\n" + "-"*63 + "\n")

def run_spinner(label, iterations=10, speed=0.04):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    for i in range(iterations):
        frame = frames[i % len(frames)]
        sys.stdout.write(f"\r{Fore.CYAN}[{frame}] {label}")
        sys.stdout.flush()
        time.sleep(speed)
    sys.stdout.write(f"\r{Fore.GREEN}[✔] {label} - COMPLETE\n")
    sys.stdout.flush()

def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except ValueError:
        return False

def parse_logs(log_filepath):
    if not os.path.exists(log_filepath):
        print(Fore.RED + f"\n[!] Error: Target log file '{log_filepath}' does not exist.")
        return None, 0
    if not os.path.isfile(log_filepath):
        print(Fore.RED + f"\n[!] Error: '{log_filepath}' is a directory, not a log file.")
        return None, 0

    suspicious_ips = []
    total_lines = 0
    
    log_regex_pattern = r"(?:Failed password for(?: invalid user)? \S+ from|Invalid user \S+ from) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    try:
        with open(log_filepath, "r", encoding="utf-8", errors="ignore") as file_stream:
            for line in file_stream:
                total_lines += 1
                matched_ip = re.search(log_regex_pattern, line)
                if matched_ip:
                    suspicious_ips.append(matched_ip.group(1))
    except PermissionError:
        print(Fore.RED + f"\n[!] Error: Permission denied. Try running with 'sudo'.")
        return None, 0
    except Exception as e:
        print(Fore.RED + f"\n[!] Error reading file: {e}")
        return None, 0

    return Counter(suspicious_ips), total_lines

def enrich_ip(ip_address):
    if not is_public_ip(ip_address):
        return {"country": "LOCAL", "city": "Internal Network", "org": "Loopback / Private Subnet"}
        
    api_endpoint = f"https://ipinfo.io/{ip_address}/json"
    try:
        response = requests.get(api_endpoint, timeout=3)
        if response.status_code == 200:
            payload = response.json()
            return {
                "country": payload.get("country", "N/A"),
                "city": payload.get("city", "N/A"),
                "org": payload.get("org", "N/A")
            }
    except requests.exceptions.RequestException:
        pass
    return {"country": "N/A", "city": "Lookup Failed", "org": "N/A"}

def block_ip_iptables(ip_address):
    if not is_public_ip(ip_address):
        print(Fore.YELLOW + f"[-] Skipping local/private IP ({ip_address}) - iptables rule not required.")
        return False
    try:
        # Utilisation de la commande native iptables pour bloquer l'IP au niveau du noyau
        result = subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], capture_output=True, text=True, check=True)
        print(Fore.GREEN + f"[+] ACTIVE DEFENSE SUCCESS: IP {ip_address} dropped via iptables.")
        return True
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[!] iptables Error: Failed to block {ip_address}. Are you running with 'sudo'? ({e.stderr.strip()})")
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Error executing firewall command: {e}")
        return False

def export_results(filename, threat_data):
    try:
        if filename.endswith(".json"):
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(threat_data, f, indent=4)
            print(Fore.GREEN + f"\n[+] Exported JSON report to: {filename}")
        elif filename.endswith(".csv"):
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Failed Attempts", "Country", "City", "ISP/Org"])
                for item in threat_data:
                    writer.writerow([item["ip"], item["attempts"], item["country"], item["city"], item["org"]])
            print(Fore.GREEN + f"\n[+] Exported CSV report to: {filename}")
    except Exception as e:
        print(Fore.RED + f"\n[!] Error exporting report: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vigilant-X - Autonomous Threat Intelligence & Log Forensics", add_help=False)
    parser.add_argument("logfile", nargs="?", help="Path to targeted log file")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Failure count threshold to flag threats (default: 3)")
    parser.add_argument("-o", "--output", type=str, help="Export results to file (.json or .csv)")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    
    args = parser.parse_args()

    if args.help:
        print(Fore.CYAN + "Vigilant-X SecOps Engine - Help Menu")
        print(Fore.YELLOW + "Usage: python3 Vigilant-X.py <logfile> [options]\n")
        print(Fore.WHITE + "Options:")
        print("  -t, --threshold INT    Minimum failed attempts to flag an IP (default: 3)")
        print("  -o, --output FILE      Export threat intelligence report (.json or .csv)")
        print("  -h, --help             Show this help message and exit\n")
        sys.exit(0)

    if not args.logfile:
        render_banner()
        print(Fore.RED + Style.BRIGHT + "[!] Error: No target log file specified.")
        print(Fore.YELLOW + "[*] Please provide a log file path to begin analysis.")
        print(Fore.WHITE + "[*] Example : python3 Vigilant-X.py [your_file.log]")
        print(Fore.CYAN + "[*] Tip     : Type 'python3 Vigilant-X.py --help' for more options.\n")
        sys.exit(1)

    render_banner()
    
    run_spinner("Booting Vigilant-X SecOps Engine")
    run_spinner(f"Ingesting log telemetry ({args.logfile})")
    
    ip_counters, total_lines_parsed = parse_logs(args.logfile)

    if ip_counters is not None:
        run_spinner("Parsing failure counters & threshold filters")
        print(Fore.YELLOW + "\n===================== INCIDENT REPORT =====================")
        
        detected_threats = []
        index_counter = 1
        for ip_address, failure_count in ip_counters.items():
            if failure_count >= args.threshold:
                run_spinner(f"Querying Threat Intel API -> {ip_address}", iterations=5, speed=0.02)
                intel = enrich_ip(ip_address)
                
                threat_entry = {
                    "index": index_counter,
                    "ip": ip_address,
                    "attempts": failure_count,
                    "country": intel["country"],
                    "city": intel["city"],
                    "org": intel["org"]
                }
                detected_threats.append(threat_entry)
                
                print(Fore.RED + Style.BRIGHT + f"\n[{index_counter}] HIGH SEVERITY ALERT: Hostile IP Detected -> {ip_address}")
                print(Fore.WHITE + f"    ├── Failed Login Count : {failure_count}")
                print(Fore.CYAN +  f"    └── Threat Intel Data  : Country: {intel['country']} | City: {intel['city']} | ISP: {intel['org']}")
                index_counter += 1
                
        print(Fore.YELLOW + "\n=================== METRICS & FORENSICS ===================")
        print(Fore.WHITE + f"  ├── Total Log Lines Processed : {total_lines_parsed}")
        print(Fore.WHITE + f"  ├── Unique IPs Identified      : {len(ip_counters)}")
        print(Fore.WHITE + f"  └── Threshold Trigger Applied  : >= {args.threshold} attempts")
        print(Fore.YELLOW + "============================================================")
        
        if not detected_threats:
            print(Fore.GREEN + Style.BRIGHT + "[+] SCAN STATUS: Clean. No malicious actors crossed threshold.")
        else:
            print(Fore.RED + Style.BRIGHT + f"[!] SCAN STATUS: Threat vectors found! Total flagged: {len(detected_threats)}")
            print(Fore.YELLOW + "============================================================")

            # Menu interactif de contre-mesure active via iptables
            print(Fore.CYAN + Style.BRIGHT + "\n[?] ACTIVE DEFENSE INTERFACE:")
            print(Fore.WHITE + "    - Enter space-separated numbers to block specific IPs (e.g., 1 3)")
            print(Fore.WHITE + "    - Type 'all' to block all detected threats instantly")
            print(Fore.WHITE + "    - Press Enter to skip and exit without blocking")
            
            choice = input(Fore.YELLOW + "\n[s4yem@Vigilant-X] Select action -> " + Style.RESET_ALL).strip().lower()

            if choice == "all":
                print(Fore.RED + "\n[!] Executing mass mitigation: Dropping all flagged threat IPs...")
                for threat in detected_threats:
                    block_ip_iptables(threat["ip"])
            elif choice:
                try:
                    selected_indices = [int(x) for x in choice.split()]
                    for idx in selected_indices:
                        matched_threat = next((t for t in detected_threats if t["index"] == idx), None)
                        if matched_threat:
                            print(Fore.YELLOW + f"\n[*] Applying counter-measure for target [{idx}]...")
                            block_ip_iptables(matched_threat["ip"])
                        else:
                            print(Fore.RED + f"[!] Warning: Index [{idx}] is invalid or not found.")
                except ValueError:
                    print(Fore.RED + "[!] Error: Invalid input format. Expected numbers or 'all'.")

        if args.output:
            export_results(args.output, detected_threats)
