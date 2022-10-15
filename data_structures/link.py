class Link:
    ip: str
    program: str
    in_packets: str
    out_packets: str

    def __init__(self, ip:str, program:str, in_packets:str, out_packets:str):
        self.ip = ip
        self.program = program
        self.in_packets = in_packets
        self.out_packets = out_packets
