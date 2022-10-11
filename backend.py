# my modules
from sniffer import PacketSniffer
from server import run_server

def main():
    # sniff
    packet_sniffer = PacketSniffer()
    packet_sniffer.sniff_packets()
    run_server()

if __name__ == "__main__":
    main()
