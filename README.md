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

The whole project can be run using the command  `make run` (which runs `sudo python3 backend.py`) from the main directory.

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

## License and Libraries
This project uses many open-source Python libraries besides the PSF LICENSE for Python 3's built-in libraries.
This includes the Python library's inclusion of the WIDE Project for getaddrinfo function in socket.
More on Python's licenses can be seen [here](https://docs.python.org/3/license.html) at the time of this README.

The non-standar libraries used and their licenses are as follows:
+ psutil: BSD 3-Clause License
+ flask: BSD-3-Clause Source License
+ scapy: GNU General Public License, version 2

BSD 3-Clause is compatible with The GNU GPL,
and the GNU GPL requires release of derivative code which this to be release under a GPL License.
This is to say BSD libraries can be used in GPL projects but GPL cannot be used in any other.
Because of this, Remorafish's Backend is to be released under the GPLv2.0 License
as of the updating of this README.

\- Evan Witthun (emwitthun@gmail.com, witthun1759@uwlax.edu)
