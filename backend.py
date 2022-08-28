import netifaces
from scapy.all import *
from socket import gethostbyaddr
from psutil import net_connections, Process

seen_ips = {}

def main():
    # get my address
    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            for ip_interfaces in iface_details[netifaces.AF_INET]:
                for key, ip_add in ip_interfaces.items():
                    if key == 'addr' and ip_add != '127.0.0.1':
                        print(ip_add)
                        seen_ips[ip_add] = 'localhost'
    # sniff
    sniff_packets()

def reverse_ip_lookup(address):
    # either I've seen this before
    if address in seen_ips:
        return seen_ips[address]
    else:
        # or I have to look it up
        try:
            host_tuple = gethostbyaddr(address)
            seen_ips[address] = host_tuple[0]
            return host_tuple[0]
        except socket.herror:
            seen_ips[address] = "no hostname"
            return "no hostname"

def associate_port_with_process(socket):
    for connection in net_connections():
        if connection.laddr.port == socket:
            return Process(connection.pid).name()
        else:
            return "no process found"

def process_packet(packet):
    print("--------------------------------")
    # the summary of packets
    print(packet.summary())
    # print the source and destination of IP packets
    if IP in packet:
        src_ip = packet[IP].src
        print("src: ", src_ip, reverse_ip_lookup(src_ip))
        dest_ip = packet[IP].dst
        print("dest: ", dest_ip, reverse_ip_lookup(dest_ip))
    # print the process associated with the packet
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        print("src port: ", sport, ", process: ", associate_port_with_process(sport))
        print("dest port: ", dport, ", process: ", associate_port_with_process(dport))

def sniff_packets():
    # runs until killed
    capture = sniff(prn=process_packet)
    # print(capture.summary())

if __name__ == "__main__":
    main()
