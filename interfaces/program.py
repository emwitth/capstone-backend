# This contain an inerface (ie class to just store data)
# for the program pieces of the JSON that will be sent to the frontend.
from constants import *
from datetime import datetime
from interfaces.ip_interfaces import IPNodeConnection

class ProgInfo:
    name:str
    socket:str
    timestamp:str
    # TODO: add pid for differentiation between instances of same proc

    def __init__(self, socket:str, name:str) -> None:
        self.name = name
        self.socket = socket
        self.update_timestamp()

    def update_timestamp(self):
        # update the timestamp so we know how recently this was associated with the socket
        self.timestamp = datetime.now()

    def __str__(self):
        return "{}(socket:{}) as of {}".format(self.name, self.socket, self.timestamp)

    def __hash__(self):
        return hash(self.name) + hash(self.socket)

class ProgNode:
    program:ProgInfo
    tot_packets:int
    ip_cons:dict

    def __init__(self, program:ProgInfo, ip:str, role:str) -> None:
        self.program = program.name
        # if we have the case where we don't have a process associated,
        # we still want to have a catchall node "no process"
        # we add that node in the beginning, but before any packets
        # have been parsed, so we want to set our count to 0 in that case
        if ip == NO_IP:
            self.tot_packets = 0
            self.ip_cons = {}
        else:
            self.tot_packets = 1
            self.ip_cons = {}
            self.ip_cons[ip] = self.ip_node_from_role(ip, role)

    def updateInfo(self, ip, role):
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

    def ip_node_from_role(self, ip, role) -> IPNodeConnection:
        if role == SRC:
            return IPNodeConnection(ip, 1, 0)
        else:
            return IPNodeConnection(ip, 0, 1)

    def print_info(self):
        print(LINE)
        print(self.__str__())
        print("Connections:")
        for con in self.ip_cons:
            print("-- {}".format(self.ip_cons[con]))

    def __str__(self):
        return "{}, packets:{}".format(self.program, self.tot_packets)
