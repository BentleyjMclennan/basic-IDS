import json
from alert import email_alert
import os
from scapy.all import sniff, ARP

def load_whitelist(path: str = "whitelist.json") -> set:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(base_dir, path)
    with open(full_path) as f:
        return set(json.load(f)["whitelist"])

WHITELIST = load_whitelist()

def handle_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP "who-has" (request)
        mac = packet[ARP].hwsrc.lower()
        if mac not in WHITELIST:
            email_alert("Unapproved MAC " + mac + " has joined the network!", "Unapproved MAC " + mac + " has joined the network!", "-insert your alert email here-" )

sniff(filter="arp", prn=handle_packet, store=False)
