# This contain a class for the packet information
# that will be sent to the frontend.
from scapy.all import packet
from scapy.utils import hexdump


class PacketInfo:
    summary:str
    src:str
    dest:str
    src_name:str
    dest_name:str
    port:str
    packet: packet.Packet

    def __init__(self, summary:str, src:str, src_name:str, dest:str, dest_name:str, port:str, packet:packet.Packet):
        self.summary = summary
        self.src = src
        self.dest = dest
        self.src_name = src_name
        self.dest_name = dest_name
        self.port = port
        self.packet = packet

    def __str__(self):
        return self.summary + " -- " + self.src_name + "-->" + self.dest_name

    def get_info(self):

        return {
        "summary": self.summary,
        "src": self.src,
        "dest": self.dest,
        "src_name": self.src_name,
        "dest_name": self.dest_name,
        "port": self.port,
        "hex": hexdump(self.packet, True)
        }
