#!/usr/bin/python3

# python and third-party modules
import netifaces
from scapy.all import *
from socket import gethostbyaddr
from psutil import net_connections, Process
from datetime import datetime

# my modules
from constants import *
from data_structures.ip_interfaces import IPNode, IPNodeConnection
from data_structures.program import ProgNode, ProgInfo

PRINT_PACKET_INFO = True

emptyProcess: ProgInfo
seen_ips = {}
ip_nodes = {}
proc_nodes = {}
my_ip = ""

# items to become the JSON object
prog_nodes = {}
ip_nodes = {}

def main():
    # add the catchall node for "no process"
    global emptyProcess
    emptyProcess = ProgInfo(NO_PROC, NO_PORT, NO_PROC)
    prog_nodes[emptyProcess] = ProgNode(emptyProcess, NO_IP, NO_ROLE)
    # get my address
    getMyAddr()
    # sniff
    sniff_packets()

def getMyAddr():
    global my_ip
    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            for ip_interfaces in iface_details[netifaces.AF_INET]:
                for key, ip_add in ip_interfaces.items():
                    # print(key, ip_add)
                    if key == 'addr' and ip_add != '127.0.0.1':
                        my_ip = ip_add;
                        print(my_ip)
                        seen_ips[ip_add] = 'localhost'

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
            seen_ips[address] = NO_HOSTNAME
            return NO_HOSTNAME

def check_if_src_or_dest(src, dest):
    if src == my_ip:
        return SRC
    elif dest == my_ip:
        return DEST

def associate_port_with_process(socket) -> ProgInfo:
    process_and_timestamp = "";
    # search for socket in current connections
    for connection in net_connections():
        if connection.laddr.port == socket:
            # update info if is in proc_nodes, else make new info class
            if socket in proc_nodes:
                proc_nodes[socket].update_timestamp()
            else:
                process = ProgInfo(Process(connection.pid).name(), socket, connection.pid)
                proc_nodes[socket] = process
            return proc_nodes[socket]
    # if the loop fails to find the socket, the socket is no longer being used
    # return the last associated process, or nothing if there is none
    if process_and_timestamp == "":
        if socket in proc_nodes:
            return proc_nodes[socket]
        else:
            return ProfInfo(socket, NO_PROC)
    return ProfInfo(socket, NO_PROC)

def update_node_info(src, dest, role, src_name, dest_name, process):
    # decide where I am src or dest and set appropriately
    if role == SRC:
        their_ip = dest
        their_name = dest_name
    else:
        their_ip = src
        their_name = src_name
    # handle case where there is no associated process
    global emptyProcess
    if process.name == NO_PROC:
        if emptyProcess in prog_nodes:
            prog_nodes[emptyProcess].updateInfo(their_ip, role)
    # if I've seen process before, have to update
    # else, make a new one
    elif process in prog_nodes:
        prog_nodes[process].updateInfo(their_ip, role)
    else:
        prog_nodes[process] = ProgNode(process, their_ip, role)
    # if I've seen ip before, have to update
    # else, make a new one
    if their_ip in ip_nodes:
        ip_nodes[their_ip].updateInfo()
    else:
        ip_nodes[their_ip] = IPNode(their_ip, their_name)

def process_packet(packet):
    # variables 'global' to this function so I can use them outside of if
    packet_role = NO_ROLE
    src_ip = NO_IP
    dest_ip = NO_IP
    src_hostname = NO_HOSTNAME
    dest_hostname = NO_HOSTNAME
    port = NO_PORT
    process = ProgInfo(NO_PROC, NO_PORT, NO_PROC)
    # print scapy's summary of the packet
    if PRINT_PACKET_INFO:
        print(LINE)
        # the summary of packets
        print(packet.summary())
    # parse the source and destination of IP packets
    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        packet_role = check_if_src_or_dest(src_ip, dest_ip)
        src_hostname = reverse_ip_lookup(src_ip)
        dest_hostname = reverse_ip_lookup(dest_ip)
        if PRINT_PACKET_INFO :
            print("src: ", src_ip, src_hostname)
            print("dest: ", dest_ip, dest_hostname)
    # parse the source and destination of IPv6 packets
    if IPv6 in packet:
        src_ip = packet[IPv6].src
        dest_ip = packet[IPv6].dst
        print(src_ip, dest_ip)
        src_hostname = reverse_ip_lookup(src_ip)
        dest_hostname = reverse_ip_lookup(dest_ip)
        if PRINT_PACKET_INFO :
            print("src: ", src_ip, src_hostname)
            print("dest: ", dest_ip, dest_hostname)
    # parse the process associated with the packet
    if TCP in packet:
        if packet_role == SRC:
            port = packet[TCP].sport
        elif packet_role == DEST:
            port = packet[TCP].dport
        # should return a ProgInfo containing the info needed
        process = associate_port_with_process(port)
        if PRINT_PACKET_INFO:
            print("I am a packet with a {} associated with {}".format
            (
            packet_role, process
            ))
    # update count we have stored to send to frontend
    update_node_info(src_ip, dest_ip, packet_role,
                    src_hostname, dest_hostname, process);

def sniff_packets():
    # runs until killed
    capture = AsyncSniffer(prn=process_packet, count=20)
    capture.start()
    capture.join()
    for prog in prog_nodes:
        prog_nodes[prog].print_info()
    for ip in ip_nodes:
        ip_nodes[ip].print_info()

if __name__ == "__main__":
    main()
