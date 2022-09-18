# This contains inerfaces (ie classes to just store data)
# for the ip pieces of the JSON that will be sent to the frontend.
from constants import *

class IPNode:
    ip:str
    name:str
    tot_packets:int

    def __init__(self, ip:str, name:str) -> None:
        self.ip = ip
        self.name = name
        self.tot_packets = 1

    def updateInfo(self):
        self.tot_packets += 1

    def print_info(self):
        print(LINE)
        print("{}({}), tot. packets:{}".format(self.ip, self.name, self.tot_packets))

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
