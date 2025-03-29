from scapy.all import sniff

# Fonction pour afficher les paquets capturés
def packet_callback(packet):
    print(f"Packet captured: {packet.summary()}")

# Démarre la capture des paquets
sniff(prn=packet_callback, store=0)
