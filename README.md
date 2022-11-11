# capstone-backend
This is the backend code for my capstone for a Software Engineering Graduate degree at University of Wisconsin Lacrosse.
It in conjunction with the [Frontend](https://github.com/emwitth/capstone-frontend).
This code is meant as a (relatively) portable application to be run on linux for network analysis.
I have provisionally named this program *Remora Fish* over its similarity to, and thus simbiotic relationship with, Wireshark.

## running and packages
This project is written in python3 code and requires several packages to be installed:
 + scapy
 + flask
 + psutil (should be included with python3 automatically)
 + netifaces (should be included with python3 automatically)

The whole project can be run using the command `sudo python3 backend.py` from the main directory.

## project structure
The backend's purpose is in two parts: 
 1. to sniff packets and infer information about them, 
 2. to produce an API for accessing the information the sniffer produces.

The code is thus also setup in two pieces:
 1. **sniffer.py** for scapy sniffing and building data structures
 2. **server.py** for serving with flask, providing endpoints

**backend.py**, the main file, instantiates an instance of the sniffer class and provides it to the server class to access when http requests are made.

There is a constants.py file that includes constants. Inside, the `print_packet_info` boolean constant can be marked true to include some packet information printed to standard out as they are sniffed.

The **data_structures** folder contains the classes that make up the graph data structure. These classes are used by the sniffer. **server.py** has no knowledge of these structures. All information gathered is passed through the server to **sniffer.py** to modify or return information from the data structure.

\- Evan Witthun (emwitthun@gmail.com, witthun1759@uwlax.edu)
