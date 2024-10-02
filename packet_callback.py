from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

        # Display payload if it's TCP or UDP
        if TCP in packet:
            print(f"TCP Payload: {bytes(packet[TCP]).hex()}")
        elif UDP in packet:
            print(f"UDP Payload: {bytes(packet[UDP]).hex()}")
        elif ICMP in packet:
            print(f"ICMP Packet: {bytes(packet[ICMP]).hex()}")

# Start sniffing packets
print("Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=0)
