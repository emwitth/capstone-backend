# This contain a class for the packet information
# that will be sent to the frontend.
from scapy.all import packet
from scapy.utils import hexdump


class PacketInfo:
    summary:str
    src:str
    dest:str
    src_name:set
    dest_name:set
    port:str
    program_name:str
    program_fd:str
    packet: packet.Packet

    def __init__(self, summary:str, src:str, src_name:set, dest:str, dest_name:set, port:str, program_name:str, program_fd:str, packet:packet.Packet):
        self.summary = summary
        self.src = src
        self.dest = dest
        self.src_name = src_name
        self.dest_name = dest_name
        self.port = port
        self.program_name = program_name
        self.program_fd = program_fd
        self.packet = packet

    def __str__(self):
        return self.summary + " -- " + self.src_name + "-->" + self.dest_name

    def get_info(self):
        srcn = self.src_name
        if(isinstance(srcn, set)):
            srcn = sorted(srcn)
        destn = self.dest_name
        if(isinstance(destn, set)):
            destn = sorted(destn)
        return {
        "summary": self.summary,
        "src": self.src,
        "dest": self.dest,
        "src_name": srcn,
        "dest_name": destn,
        "port": self.port,
        "program_name": self.program_name,
        "program_fd": self.program_fd,
        "hex": hexdump(self.packet, True)
        }
