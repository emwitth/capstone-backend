# This contains a class for the ip information
# that will be sent to the frontend.
from constants import *
from typing import List
from data_structures.packet import PacketInfo

class IPNode:
    ip:str
    name:str
    tot_packets:int
    packets:List[PacketInfo]

    def __init__(self, ip:str, name:str) -> None:
        self.ip = ip
        self.name = name
        self.tot_packets = 1
        self.packets = []

    def updateInfo(self, packet):
        self.tot_packets += 1
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

    def addPacket(self, packet):
        self.packets.append(packet)

class IPNodeConnection:
    ip:str
    in_packets:int
    out_packets:int

    def __init__(self, ip:str, in_packets:int, out_packets:int) -> None:
        self.ip = ip
        self.in_packets = in_packets
        self.out_packets = out_packets

    def __str__(self):
        return "{} - in:{}, out:{}".format(self.ip, self.in_packets, self.out_packets)
