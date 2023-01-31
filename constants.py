###############################
###### Global 'Constants' #####
###############################

# controls whether packet info is printed while it is sniffed
# used for debugging
PRINT_PACKET_INFO = False
PRINT_PACKET_HEX = False
PRINT_MISC_DEBUG = False

# for storing which role the packet is
# also used for easy printing, that is why not bool
SRC = "source"
DEST = "destination"

# for setting default value of varibales
NO_PROC = "no process"
NO_PORT = "no port"
NO_ROLE = "no role"
NO_IP = "no ip"
NO_HOSTNAME = "no hostname"

# for names of non-process/ip nodes
ARP_NODE_NAME = "ARP PACKETS"
DNS_NODE_NAME = "DNS PACKETS"

# for console printing
LINE = "--------------------------------"
