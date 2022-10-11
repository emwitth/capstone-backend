# my modules
from sniffer import PacketSniffer

def main():
    # sniff
    packet_sniffer = PacketSniffer()
    packet_sniffer.sniff_packets()

if __name__ == "__main__":
    main()
