# This contain an inerface (ie class to just store data)
# for the program pieces of the JSON that will be sent to the frontend.
from interfaces.ip_interfaces import IPConnection

class ProgNode:
    program:str
    tot_packets:int
    ip_cons:list

    def __init__(self, program:str, tot_packets:str) -> None:
        self.program = program
        self.tot_packets = tot_packets
        self.ip_cons = []
