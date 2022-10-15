# my modules
from sniffer import PacketSniffer
from server import Server

def main():
    # sniff
    packet_sniffer = PacketSniffer()
    # packet_sniffer.sniff_packets()
    server = Server(packet_sniffer)
    server.run_server()

if __name__ == "__main__":
    main()
