import json
from alert import email_alert
import os
from scapy.all import sniff, ARP
import urllib.request
import urllib.error

def load_whitelist(path: str = "whitelist.json") -> set:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(base_dir, path)
    with open(full_path) as f:
        return set(json.load(f)["whitelist"])
    
WHITELIST = load_whitelist()

def get_vendor(mac: str) -> str:
    try:
        url = f"https://api.macvendors.com/{mac}"
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "Unknown Vendor"
        return f"API Error ({e.code})"
    except Exception:
        return "Vendor Lookup Failed"
response = ""
def handle_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP "who-has" (request)
        mac = packet[ARP].hwsrc.lower()
        if mac not in WHITELIST:
            response = get_vendor(mac)
            email_alert("Unapproved MAC " + mac + " from vendor " + response + " has joined the network!", "Unapproved MAC " + mac +  " has joined the network!", "-input email-")

sniff(filter="arp", prn=handle_packet, store=False)
