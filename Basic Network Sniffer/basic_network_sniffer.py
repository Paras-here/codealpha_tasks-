from scapy.all import sniff

def packet_handler(packet):
    print("=" * 60)
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"[+] Source IP      : {ip_layer.src}")
        print(f"[+] Destination IP : {ip_layer.dst}")
        print(f"[+] Protocol       : {ip_layer.proto}")
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        print(f"[+] Source Port    : {tcp_layer.sport}")
        print(f"[+] Destination Port: {tcp_layer.dport}")
    elif packet.haslayer('UDP'):
        udp_layer = packet['UDP']
        print(f"[+] Source Port    : {udp_layer.sport}")
        print(f"[+] Destination Port: {udp_layer.dport}")
    if packet.haslayer('Raw'):
        raw_data = packet['Raw'].load
        print(f"[+] Payload        : {raw_data[:50]!r}")

def main():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
    main()
