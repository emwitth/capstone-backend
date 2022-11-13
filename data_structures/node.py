# This contain a generic class for the information shared by both program
# and ip node classes.
from constants import *
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List
from data_structures.packet import PacketInfo
from constants import SRC, DEST

class ProgInfo:
    name:str
    socket:str
    fd: str
    timestamp:str

    def __init__(self, name:str, socket:str, fd:str) -> None:
        self.name = name
        self.socket = socket
        self.fd = fd
        self.update_timestamp()

    def update_timestamp(self):
        # update the timestamp so we know how recently this was associated with the socket
        self.timestamp = datetime.now()

    def __str__(self):
        return "{}({}, socket:{}) as of {}".format(self.name, self.fd, self.socket, self.timestamp)

    def __hash__(self):
        return hash(self.name) + hash(self.socket) + hash(self.fd)

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()


class Link:
    ip: str
    program: ProgInfo

    def __init__(self, ip:str, program:ProgInfo):
        self.ip = ip
        self.program = program

    def __hash__(self):
        return hash(self.ip) + self.program.__hash__()

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __str__(self):
        return self.ip + "<>" + self.program.__str__()

class Node(ABC):
    is_hidden: bool
    tot_packets:int
    cons:dict
    packets:List[PacketInfo]

    def __init__(self) -> None:
        self.is_hidden = False
        self.tot_packets = 0
        self.cons = {}
        self.packets = []

    def addPacket(self, packet):
        self.packets.append(packet)

    def update(self, ipNode, progNode, role, packet):
        self.tot_packets += 1
        self.addPacket(packet)
        # if I've seen connection before, have to update
        # else, make a new one
        link = Link(ipNode.ip, progNode.program)
        con: Connection
        if link in self.cons:
            con = self.cons[link]
        else:
            con = Connection(ipNode, progNode)
            self.cons[link] = con
        # once I have it, update the packet count
        if role == SRC:
            con.update(1, 0)
        else:
            con.update(0, 1)

    def are_all_links_hidden(self):
        all_hidden = True
        for con in self.cons.values():
            if con.is_hidden == False:
                all_hidden = False
        return all_hidden

    def make_con_list(self):
        list = []
        for con in self.cons.values():
            if con.is_hidden == False:
                list.append({
                "ip": con.ip.ip,
                "program": con.program.program.__dict__,
                "in_packets": con.in_packets,
                "out_packets": con.out_packets
                })
        return list

    def get_con_with_ip(self, ip) :
        list = []
        for con in self.cons.values():
            if(con.ip.ip == ip):
                list.append({
                "ip": con.ip.ip,
                "program": con.program.program.__dict__,
                "in_packets": con.in_packets,
                "out_packets": con.out_packets
                })
        return list

    @abstractmethod
    def print_info():
        pass

class Connection:
    is_hidden: bool
    ip: Node
    program: Node
    in_packets:int
    out_packets:int

    def __init__(self, ip, program) -> None:
        self.is_hidden = False
        self.ip = ip
        self.program = program
        self.in_packets = 0
        self.out_packets = 0

    def update(self, in_packets, out_packets):
        self.in_packets += in_packets
        self.out_packets += out_packets

    def get_info(self):
        return {
        "program": self.program.program.__dict__,
        "ip_name": self.ip.name,
        "ip": self.ip.ip,
        "in_packets": self.in_packets,
        "out_packets": self.out_packets
        }

    def __str__(self):
        return "{} <> {} - in:{}, out:{}".format(self.ip.ip, self.program, self.in_packets, self.out_packets)

class IPNode(Node):
    ip:str
    name:str
    packets:List[PacketInfo]

    def __init__(self, ip:str, name:str) -> None:
        Node.__init__(self)
        self.ip = ip
        self.name = name

    def print_info(self):
        print(LINE)
        print("{}({}), tot. packets:{}".format(self.ip, self.name, self.tot_packets))

    def get_info(self):
        return {
        "ip": self.ip,
        "name": self.name,
        "tot_packets": self.tot_packets
        }

class ProgNode(Node):
    program:ProgInfo

    def __init__(self, program:ProgInfo, ip:str, role:str) -> None:
        Node.__init__(self)
        self.program = program

    def return_fields_for_json(self):
        return {"program": self.program.__dict__, "tot_packets": self.tot_packets}

    def print_info(self):
        print(LINE)
        print(self.__str__())
        print("Connections:")
        for con in self.cons.values():
            print("-- {}".format(con))

    def __str__(self):
        return "{}({}), packets:{}".format(self.program.name, self.program.fd, self.tot_packets)
