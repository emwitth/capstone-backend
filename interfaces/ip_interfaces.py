# This contains inerfaces (ie classes to just store data)
# for the ip pieces of the JSON that will be sent to the frontend.

class IPNode:
    ip:str
    tot_packets:int

    def __init__(self, ip:str, tot_packets:int) -> None:
        self.ip = ip
        self.tot_packets = tot_packets

class IPConnection:
    ip:str
    in_packets:int
    out_packets:int

    def __init__(self, ip:str, in_packets:int, out_packets:int) -> None:
        self.ip = ip
        self.in_packets = in_packets
        self.out_packets = out_packets
