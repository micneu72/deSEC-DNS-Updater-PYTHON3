#!/usr/bin/env python3
"""
----------------------------------------------------------------------------
    Script Name:     desec.py
    CreationDate:    08.03.2025
    Last Modified:   24.04.2025 14:49:41
    Copyright:       Michael N. (c)2025
    Purpose:         Aktualisiert DNS-Einträge bei desec.io mit Pushover-Benachrichtigungen
----------------------------------------------------------------------------
"""

import os
import sys
import json
import time
import argparse
import re
import subprocess
import requests
import logging
from typing import Tuple, Dict, Optional, Any, List
from datetime import datetime


def setup_logging():
    """Konfiguriert das Logging mit Zeitstempeln."""
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO
    )
    
    # Umleiten von print-Ausgaben in das Logging-System
    global original_print
    global print
    original_print = print
    
    def print_with_timestamp(*args, **kwargs):
        message = " ".join(map(str, args))
        logging.info(message)
    
    # print-Funktion ersetzen
    print = print_with_timestamp


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Update DNS entries at desec.io')
    parser.add_argument('-c', '--config', default='./desec.json',
                        help='Path to configuration file (default: ./desec.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    return parser.parse_args()


def create_default_config(config_file: str) -> None:
    """Create a default configuration file if it doesn't exist."""
    default_config = {
        "token": "enter_your_desec_token_here",
        "domain": "enter.your.domain.here",
        "subname": "enter.your.subname.here",
        "pushover": {
            "enabled": False,
            "user_key": "your_pushover_user_key",
            "app_token": "your_pushover_app_token"
        }
    }
    
    try:
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"Template file {config_file} has been created. "
              f"Please adjust the values and restart the script.")
    except Exception as e:
        print(f"Error creating template file: {e}")
        sys.exit(1)


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from a JSON file."""
    try:
        if not os.path.exists(config_file):
            print(f"Configuration file {config_file} not found! Creating template file...")
            create_default_config(config_file)
            sys.exit(0)
            
        with open(config_file, 'r') as f:
            config = json.load(f)
            
        # Check if values were successfully loaded
        if not config.get("token") or config["token"] == "enter_your_desec_token_here":
            print("Error: Token could not be read from the configuration file or has not been customized.")
            sys.exit(1)
            
        if not config.get("domain") or config["domain"] == "enter.your.domain.here":
            print("Error: Domain could not be read from the configuration file or has not been customized.")
            sys.exit(1)

        if not config.get("subname") or config["subname"] == "enter.your.subname.here":
            print("Error: subname could not be read from the configuration file or has not been customized.")
            sys.exit(1)
            
        # Ensure Pushover configuration exists, even if not enabled
        if "pushover" not in config:
            config["pushover"] = {"enabled": False}
            
        return config
    except Exception as e:
        print(f"Error loading configuration file: {e}")
        sys.exit(1)


def send_pushover_notification(config: Dict[str, Any], title: str, message: str, priority: int = 0) -> bool:
    """
    Sends a Pushover notification if the configuration is available.
    
    Args:
        config: The configuration with Pushover settings
        title: Notification title
        message: Notification text
        priority: Priority (-2 to 2, default: 0)
        
    Returns:
        bool: True if the notification was sent, otherwise False
    """
    # Check if Pushover is configured and enabled
    if not config.get("pushover", {}).get("enabled", False):
        return False
    
    pushover_config = config["pushover"]
    
    # Check if the required keys are present
    if not pushover_config.get("user_key") or not pushover_config.get("app_token"):
        return False
    
    # Send Pushover API request
    try:
        response = requests.post(
            "https://api.pushover.net/1/messages.json",
            data={
                "token": pushover_config["app_token"],
                "user": pushover_config["user_key"],
                "title": title,
                "message": message,
                "priority": priority,
                "timestamp": int(time.time())
            },
            timeout=10
        )
        
        if response.status_code == 200:
            return True
        else:
            print(f"Error sending Pushover notification: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending Pushover notification: {e}")
        return False

def check_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Überprüft, ob der übergebene String eine gültige IPv4- oder IPv6-Adresse ist.
    
    Returns:
        Tuple[bool, str]: (ist_gültig, ip_typ)
    """
    # Regulärer Ausdruck für IPv4
    ipv4_regex = r'^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    # Regulärer Ausdruck für IPv6
    ipv6_regex = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    
    # Überprüfung, ob der String mit dem IPv4-RegEx übereinstimmt
    if re.match(ipv4_regex, ip):
        # Sicherstellen, dass die Zahlen im gültigen Bereich (0-255) liegen
        octets = ip.split('.')
        for octet in octets:
            if int(octet) < 0 or int(octet) > 255:
                return False, "Invalid IP"
        return True, f"IPv4: {ip}"
    
    # Überprüfung, ob der String mit dem IPv6-RegEx übereinstimmt
    if re.match(ipv6_regex, ip):
        return True, f"IPv6: {ip}"
    
    return False, "Invalid IP"


def hostname_to_ip(hostname: str, verbose: bool = False) -> Tuple[str, str]:
    """
    Löst einen Hostnamen in IPv4- und IPv6-Adressen auf.
    
    Returns:
        Tuple[str, str]: (ipv4_list, ipv6_list)
    """
    ipv4_list = ""
    ipv6_list = ""
    
    try:
        # Versuchen, mit verschiedenen Methoden die IP-Adressen zu ermitteln
        methods = [
            ('drill', lambda: subprocess.run(['drill', hostname], stdout=subprocess.PIPE, text=True).stdout),
            ('host', lambda: subprocess.run(['host', hostname], stdout=subprocess.PIPE, text=True).stdout),
            ('dig', lambda: subprocess.run(['dig', hostname, '+short'], stdout=subprocess.PIPE, text=True).stdout),
            ('nslookup', lambda: subprocess.run(['nslookup', hostname], stdout=subprocess.PIPE, text=True).stdout)
        ]
        
        results = None
        used_method = None
        
        for method_name, method_func in methods:
            try:
                if subprocess.run(['which', method_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
                    results = method_func()
                    used_method = method_name
                    break
            except Exception:
                continue
        
        if verbose:
            print(f"Using {used_method} for DNS resolution")
        
        if not results:
            print("Error: No DNS lookup tools available (drill, host, dig, nslookup).")
            return "", ""
        
        # IP-Adressen aus den Ergebnissen extrahieren
        ip_pattern = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4})'
        ips = re.findall(ip_pattern, results)
        
        if ips and isinstance(ips[0], tuple):
            ips = [ip[0] for ip in ips]  # Extrahiere die vollständige IP aus den Tupeln
        
        # Trenne IPv4 und IPv6 Adressen
        for ip in ips:
            if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                ipv4_list = ip.strip()
            elif re.match(r'^([0-9a-fA-F]{1,4}:)', ip):
                ipv6_list = ip.strip()
        
        return ipv4_list, ipv6_list
    
    except Exception as e:
        print(f"Error resolving hostname: {e}")
        return "", ""


def get_dns_records(domain: str, subname: str, token: str) -> Tuple[List[str], List[str]]:
    """Holt A/AAAA-Records mit Schleife für weniger Code-Duplikation."""
    headers = {"Authorization": f"Token {token}"}
    record_types = ["A", "AAAA"]
    results = {"A": [], "AAAA": []}

    for record_type in record_types:
        try:
            url = f"https://desec.io/api/v1/domains/{domain}/rrsets/{subname}/{record_type}/"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 404:
                continue  # Ignoriere nicht-existente Einträge
                
            response.raise_for_status()
            results[record_type] = response.json().get("records", [])
            
        except requests.HTTPError as e:
            print(f"Fehler bei {record_type}-Record: {e}")
        except Exception as e:
            print(f"Allgemeiner Fehler bei {record_type}-Record: {e}")

    return results["A"][0], results["AAAA"][0]


def format_runtime(elapsed_time: int) -> str:
    """
    Formats the given runtime (in seconds) dynamically.Args:
        elapsed_time: Time in seconds to format
        
    Returns:
        str: Formatted runtime string
    """
    time_units = [
        (86400, "day", "days"),
        (3600, "hour", "hours"),
        (60, "minute", "minutes"),
        (1, "second", "seconds")
    ]

    if elapsed_time < 60:
        return f"Runtime: {elapsed_time} seconds"

    parts = []
    remaining = elapsed_time

    for seconds, singular, plural in time_units:
        if remaining >= seconds:
            value = remaining // seconds
            remaining %= seconds
            unit = singular if value == 1 else plural
            parts.append(f"{value} {unit}")

    return f"Runtime: {', '.join(parts)}"


def update_dns(config: Dict[str, Any], wanIPv4: str, wanIPv6: str, dnsIPv4: str, dnsIPv6: str, verbose: bool = False) -> bool:
    """
    Aktualisiert die DNS-Einträge bei desec.io, wenn sich die IPs geändert haben.
    
    Returns:
        bool: True wenn eine Aktualisierung durchgeführt wurde, sonst False
    """
    kodihost = f"{config['subname']}.{config['domain']}"
    domain = config["domain"]
    subname = config["subname"]
    token = config["token"]
    
    # Prüfen, ob sich die IPs geändert haben
    ip_changed = wanIPv4 != dnsIPv4 or wanIPv6 != dnsIPv6
    
    if ip_changed:
        print("The IPs have changed or one of them. Starting processing.")
        
        # Nachricht für Pushover vorbereiten
        change_details = []
        if wanIPv4 != dnsIPv4:
            change_details.append(f"IPv4: {dnsIPv4} → {wanIPv4}")
        if wanIPv6 != dnsIPv6:
            change_details.append(f"IPv6: {dnsIPv6} → {wanIPv6}")
        
        change_message = "\n".join(change_details)
        
        url = "https://update.dedyn.io/"
        headers = {"Authorization": f"Token {token}"}
        
        if wanIPv4 and wanIPv6:
            print(f"Both IPs are available: WAN IPv4 = '{wanIPv4}', WAN IPv6 = '{wanIPv6}'")
            params = {"hostname": kodihost, "myipv4": wanIPv4, "myipv6": wanIPv6}
        elif wanIPv4:
            print(f"Only IPv4 is available: IPv4 = '{wanIPv4}'")
            params = {"hostname": kodihost, "myipv4": wanIPv4, "myipv6": "no"}
        elif wanIPv6:
            print(f"Only IPv6 is available: IPv6 = '{wanIPv6}'")
            params = {"hostname": kodihost, "myipv4": "no", "myipv6": wanIPv6}
        else:
            print("None of the IPs are available")
            return False

        
        try:
            response = requests.get(url, headers=headers, params=params)
            
            if verbose:
                print(f"Update response: {response.text}")
            else:
                print(f"Update status: {response.status_code}")
            
            # Pushover-Benachrichtigung senden
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            notification_title = f"DNS Update for {kodihost}"
            notification_message = f"IP change on {current_time}:\n{change_message}\n\nUpdate status: {response.status_code}"
            
            send_pushover_notification(config, notification_title, notification_message)
            
            return True
        except Exception as e:
            error_message = f"Error updating DNS entries: {e}"
            print(error_message)
            
            # Fehler auch per Pushover melden
            send_pushover_notification(
                config, 
                f"DNS-Update Error for {kodihost}", 
                error_message,
                priority=1
            )
            
            return False
    else:
        print("The IPs have not changed. No action required.")
        return False


def get_current_ips(verbose: bool = False) -> Tuple[str, str]:
    """Ermittelt öffentliche IPs mit verbesserter Fehlerbehandlung"""
    services = [
        {
            "name": "Amazon AWS",
            "ipv4": "https://checkip.amazonaws.com",
            "ipv6": "https://checkipv6.amazonaws.com"
        },
        {
            "name": "icanhazip",
            "ipv4": "https://ipv4.icanhazip.com",
            "ipv6": "https://ipv6.icanhazip.com"
        }
    ]
    
    def fetch_ip(url: str) -> str:
        try:
            response = requests.get(url, timeout=3)
            return response.text.strip() if response.status_code == 200 else ""
        except:
            return ""

    return (
        next((ip for s in services if (ip := fetch_ip(s["ipv4"]))), ""),
        next((ip for s in services if (ip := fetch_ip(s["ipv6"]))), "")
    )



def main() -> None:
    """Main function of the script."""
    # Global-Deklarationen am Anfang der Funktion
    global print
    
    # Logging mit Zeitstempeln einrichten
    setup_logging()
    
    start_time = time.time()
    
    # Kommandozeilenargumente parsen
    args = parse_arguments()
    
    # Konfiguration laden
    config = load_config(args.config)
    
    # Hostname ausgeben
    kodihost = f"{config['subname']}.{config['domain']}"
    print(f"Hostname: {kodihost}")
    
    # Aktuelle IPs des Hostnamens abrufen
    dnsIPv4, dnsIPv6 = get_dns_records(config['domain'], config['subname'], config['token'])
    print(f"dnsIPv4: {dnsIPv4}, dnsIPv6: {dnsIPv6}")
    
    # Aktuelle öffentliche IPs abrufen
    wanIPv4, wanIPv6 = get_current_ips(args.verbose)
    print(f"wanIPv4: {wanIPv4}, wanIPv6: {wanIPv6}")

    # DNS-Einträge aktualisieren, wenn nötig
    update_dns(config, wanIPv4, wanIPv6, dnsIPv4, dnsIPv6, args.verbose)
    
    # Laufzeit ausgeben
    end_time = time.time()
    elapsed_time = int(end_time - start_time)
    print("\n" + format_runtime(elapsed_time))
    
    # Original print-Funktion wiederherstellen
    print = original_print

if __name__ == "__main__":
    main()
