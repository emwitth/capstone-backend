# This contains a class for the ip information
# that will be sent to the frontend.
from constants import *
from typing import List
from data_structures.node import Node
from data_structures.packet import PacketInfo

class IPNode(Node):
    ip:str
    name:str
    tot_packets:int
    packets:List[PacketInfo]

    def __init__(self, ip:str, name:str) -> None:
        Node.__init__(self)
        self.ip = ip
        self.name = name

    def updateInfo(self, packet):
        self.packets.append(packet)

    def print_info(self):
        print(LINE)
        print("{}({}), tot. packets:{}".format(self.ip, self.name, self.tot_packets))

    def get_info(self):
        return {
        "ip": self.ip,
        "name": self.name,
        "tot_packets": self.tot_packets
        }
