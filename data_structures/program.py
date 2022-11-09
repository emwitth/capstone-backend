# This contain a class for the program information
# that will be sent to the frontend.
from constants import *
from datetime import datetime
from data_structures.node import Node
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

class ProgNode(Node):
    program:ProgInfo

    def __init__(self, program:ProgInfo, ip:str, role:str) -> None:
        Node.__init__(self)
        self.program = program
        # if we have the case where we don't have a process associated,
        # we still want to have a catchall node "no process"
        # we add that node in the beginning, but before any packets
        # have been parsed, so we want to set our count to 0 in that case
        if ip != NO_IP:
            self.tot_packets = 1
            self.cons[ip] = self.ip_node_from_role(ip, role)

    def updateInfo(self, ip, role, packet):
        self.tot_packets += 1
        # if I've seen ip before, have to update
        # else, make a new one
        if ip in self.cons:
            if role == SRC:
                self.cons[ip].in_packets += 1
            else:
                self.cons[ip].out_packets += 1
        else:
            self.cons[ip] = self.ip_node_from_role(ip, role)
        # add packet to list of packets
        self.packets.append(packet)

    def return_fields_for_json(self):
        return {"program": self.program.__dict__, "tot_packets": self.tot_packets}

    def get_con_with_ip(self, ip) :
        list = []
        for con in self.cons.values():
            if(con.ip == ip):
                list.append(Link(con.ip, self.program.__dict__, con.in_packets, con.out_packets).__dict__)
        return list

    def print_info(self):
        print(LINE)
        print(self.__str__())
        print("Connections:")
        for con in self.cons:
            print("-- {}".format(self.cons[con]))

    def __str__(self):
        return "{}({}), packets:{}".format(self.program.name, self.program.fd, self.tot_packets)
