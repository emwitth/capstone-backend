import netifaces
from scapy.all import *
from socket import gethostbyaddr
from psutil import net_connections, Process

SRC = "source"
DEST = "destination"

seen_ips = {}
my_ip = ""

def main():
    # get my address
    global my_ip
    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            for ip_interfaces in iface_details[netifaces.AF_INET]:
                for key, ip_add in ip_interfaces.items():
                    if key == 'addr' and ip_add != '127.0.0.1':
                        my_ip = ip_add;
                        print(my_ip)
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

def check_if_src_or_dest(src, dest):
    if src == my_ip:
        return SRC
    elif dest == my_ip:
        return DEST

def associate_port_with_process(socket):
    for connection in net_connections():
        if connection.laddr.port == socket:
            return Process(connection.pid).name()
        else:
            return "no process"
    return "no process"

def process_packet(packet):
    print("--------------------------------")
    # the summary of packets
    print(packet.summary())
    # print the source and destination of IP packets
    packet_role = "no role";
    if IP in packet:
        src_ip = packet[IP].src
        print("src: ", src_ip, reverse_ip_lookup(src_ip))
        dest_ip = packet[IP].dst
        print("dest: ", dest_ip, reverse_ip_lookup(dest_ip))
        packet_role = check_if_src_or_dest(src_ip, dest_ip)
    # print the process associated with the packet
    port = "no port"
    if TCP in packet:
        if packet_role == SRC:
            port = packet[TCP].sport
        elif packet_role == DEST:
            port = packet[TCP].dport
        print("I am a packet with a {} associated with {}".format(packet_role, associate_port_with_process(port)))

def sniff_packets():
    # runs until killed
    capture = sniff(prn=process_packet)
    # print(capture.summary())

if __name__ == "__main__":
    main()
