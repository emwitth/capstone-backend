# This contain a generic class for the information shared by both program
# and ip node classes.
from abc import ABC, abstractmethod
from typing import List
from data_structures.packet import PacketInfo
from data_structures.link import Link
from constants import SRC, DEST

class Connection:
    ip:str
    in_packets:int
    out_packets:int

    def __init__(self, ip:str, in_packets:int, out_packets:int) -> None:
        self.ip = ip
        self.in_packets = in_packets
        self.out_packets = out_packets

    def __str__(self):
        return "{} - in:{}, out:{}".format(self.ip, self.in_packets, self.out_packets)

class Node(ABC):
    is_hidden: bool
    tot_packets:int
    cons:dict
    packets:List[PacketInfo]

    def __init__(self) -> None:
        self.is_hidden = True
        self.tot_packets = 0
        self.cons = {}
        self.packets = []

    def addPacket(self, packet):
        self.packets.append(packet)

    def ip_node_from_role(self, ip, role) -> Connection:
        if role == SRC:
            return Connection(ip, 1, 0)
        else:
            return Connection(ip, 0, 1)

    def make_con_list(self):
        list = []
        for con in self.cons.values():
            list.append(Link(con.ip, self.program.__dict__, con.in_packets, con.out_packets).__dict__)
        return list

    @abstractmethod
    def updateInfo():
        pass

    @abstractmethod
    def print_info():
        pass
