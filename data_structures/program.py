# This contain a class for the program information
# that will be sent to the frontend.
from constants import *
from datetime import datetime
from typing import List
from data_structures.ip import IPNodeConnection
from data_structures.link import Link
from data_structures.packet import PacketInfo

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

class ProgNode:
    program:ProgInfo
    tot_packets:int
    ip_cons:dict
    packets:List[PacketInfo]

    def __init__(self, program:ProgInfo, ip:str, role:str) -> None:
        self.program = program
        # if we have the case where we don't have a process associated,
        # we still want to have a catchall node "no process"
        # we add that node in the beginning, but before any packets
        # have been parsed, so we want to set our count to 0 in that case
        if ip == NO_IP:
            self.tot_packets = 0
            self.ip_cons = {}
            self.packets = []
        else:
            self.tot_packets = 1
            self.ip_cons = {}
            self.ip_cons[ip] = self.ip_node_from_role(ip, role)
            self.packets = []

    def addPacket(self, packet):
        self.packets.append(packet)

    def updateInfo(self, ip, role, packet):
        self.tot_packets += 1
        # if I've seen ip before, have to update
        # else, make a new one
        if ip in self.ip_cons:
            if role == SRC:
                self.ip_cons[ip].in_packets += 1
            else:
                self.ip_cons[ip].out_packets += 1
        else:
            self.ip_cons[ip] = self.ip_node_from_role(ip, role)
        # add packet to list of packets
        self.packets.append(packet)

    def ip_node_from_role(self, ip, role) -> IPNodeConnection:
        if role == SRC:
            return IPNodeConnection(ip, 1, 0)
        else:
            return IPNodeConnection(ip, 0, 1)

    def return_fields_for_json(self):
        return {"program": self.program.__dict__, "tot_packets": self.tot_packets}

    def make_con_list(self):
        list = []
        for con in self.ip_cons.values():
            list.append(Link(con.ip, self.program.__dict__, con.in_packets, con.out_packets).__dict__)
        return list

    def print_info(self):
        print(LINE)
        print(self.__str__())
        print("Connections:")
        for con in self.ip_cons:
            print("-- {}".format(self.ip_cons[con]))

    def __str__(self):
        return "{}({}), packets:{}".format(self.program.name, self.program.fd, self.tot_packets)
