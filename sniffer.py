from scapy.all import *

# Fungsi untuk mendeteksi anomali dalam paket
def detect_anomalies(packet):
    # Misalnya, kita ingin mendeteksi paket dengan flag tertentu atau ukuran yang tidak biasa
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Deteksi ICMP, TCP atau UDP
        if packet.haslayer(ICMP):
            print(f"[ICMP Detected] Source: {ip_src} -> Destination: {ip_dst}")
        elif packet.haslayer(TCP):
            print(f"[TCP Detected] Source: {ip_src} -> Destination: {ip_dst} | Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"[UDP Detected] Source: {ip_src} -> Destination: {ip_dst} | Port: {packet[UDP].dport}")
        
        # Deteksi paket yang sangat kecil atau besar
        if len(packet) < 50:
            print(f"[Small Packet Detected] Size: {len(packet)} bytes | Source: {ip_src} -> {ip_dst}")
        elif len(packet) > 1500:
            print(f"[Large Packet Detected] Size: {len(packet)} bytes | Source: {ip_src} -> {ip_dst}")

# Fungsi untuk memulai packet sniffer
def start_sniffer():
    print("Starting network traffic monitoring...")
    sniff(prn=detect_anomalies, store=0)  # Memulai sniffing paket tanpa menyimpan hasilnya

# Menjalankan sniffer
if __name__ == "__main__":
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nStopped by user.")
