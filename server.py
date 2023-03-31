from flask import Flask, jsonify, request, make_response, send_from_directory
import os
from shutil import rmtree
from datetime import datetime

# my modules
from sniffer import PacketSniffer

class Server:
    app: Flask
    packet_sniffer: PacketSniffer

    def __init__(self, packet_sniffer: PacketSniffer):
        self.packet_sniffer = packet_sniffer
        self.app = Flask(__name__)
        self.initalize_urls()

    def graph_data(self):
        return jsonify(self.packet_sniffer.get_graph_json())

    def sniff_controller(self, on):
        params = request.get_json()
        if(on.title() == "True"):
            self.packet_sniffer.sniff_packets()
            return jsonify("Packet Sniffer Started")
        elif(on.title() == "False"):
            if(params["sessionName"] == ""):
                print("There is no session name.")
                self.packet_sniffer.stop_sniffing()
            else:
                print("I got a session name: {}".format(params["sessionName"]))
                folder_path = "sessions/{}".format(params["sessionName"])
                if(os.path.exists(folder_path)):
                    # session exists shouldn't overwrite it, throw an error
                    return make_response(jsonify({"message": "Session name already exists. Try another one."}), 400)
                else:
                    # create folder for session
                    os.makedirs(folder_path)
                    self.packet_sniffer.stop_sniffing()
                    self.packet_sniffer.write_pcap("{}/{}".format(folder_path, params["sessionName"]))
                    self.packet_sniffer.write_port_procs(folder_path)
                    self.packet_sniffer.write_icmp_procs(folder_path)
                    file = open("{}/description.txt".format(folder_path), "w")
                    file.write("{}\n".format(params["description"]))
                    file.close()
                    file = open("{}/timestamp.txt".format(folder_path), "w")
                    file.write("{}\n".format(datetime.now()))
                    file.close()
            return jsonify("Packet Sniffer Stopped")
        return jsonify("Failed")

    def list_sessions(self):
        sessions = os.listdir("sessions")
        print(sessions)
        session_list = []
        for session in sessions:
            file = open("sessions/{}/description.txt".format(session), "r")
            description = file.read()
            file = open("sessions/{}/timestamp.txt".format(session), "r")
            timestamp = file.read()
            session_list.append({
            "name": session,
            "description": description,
            "timestamp":timestamp
            })
        return jsonify(session_list)

    def delete_session(self, name):
        print(name)
        path = "sessions/{}".format(name)
        if os.path.isdir(path):
            rmtree(path)
            return make_response(jsonify("Session {} deleted successfully".format(name)), 200)
        return make_response(jsonify("Session {} does not exist.".format(name)), 404)

    def get_pcap(self, name):
        path = "sessions/{}".format(name)
        file = "{}.pcap".format(name)
        return send_from_directory(path, file, as_attachment=True)

    def load_session(self, name):
        path = "sessions/{}".format(name)
        file = "{}.pcap".format(name)
        self.packet_sniffer.read_port_procs(path)
        self.packet_sniffer.read_icmp_procs(path)
        self.packet_sniffer.isLoadedSession = True
        self.packet_sniffer.read_pcap("{}/{}".format(path, file))
        return jsonify("Read Pcap")

    def node_packets(self):
        params = request.get_json()
        if(params["isIP"] == True):
            result = self.packet_sniffer.get_ip_node_packets(params["ip"])
            return jsonify(result)
        else:
            result = self.packet_sniffer.get_prog_node_packets(params["name"], params["port"], params["fd"])
            return jsonify(result)
        return jsonify("Failed")

    def link_packets(self):
        params = request.get_json()
        result = self.packet_sniffer.get_link_packets(params["ip"], params["name"], params["port"], params["fd"])
        return jsonify(result)

    def hide(self):
        params = request.get_json()
        if params["type"] == "program" :
            self.packet_sniffer.hide_prog_node(params["prog_name"], params["port"], params["fd"])
        if params["type"] == "ip":
            self.packet_sniffer.hide_ip_node(params["ip"])
        if params["type"] == "link":
            self.packet_sniffer.hide_link(params["ip"], params["prog_name"], params["port"], params["fd"])
        return params

    def get_hidden_items(self):
        return jsonify(self.packet_sniffer.get_hidden_items());

    def show(self):
        params = request.get_json()
        if params["type"] == "program" :
            self.packet_sniffer.show_prog_node(params["prog_name"], params["port"], params["fd"])
        if params["type"] == "ip":
            self.packet_sniffer.show_ip_node(params["ip"])
        if params["type"] == "link":
            self.packet_sniffer.show_link(params["ip"], params["prog_name"], params["port"], params["fd"])
        # so the page can update with the new hidden items
        return jsonify(self.packet_sniffer.get_hidden_items());

    def initalize_urls(self):
        self.app.add_url_rule('/api/graph-data', 'graph_data', self.graph_data)
        self.app.add_url_rule('/api/sniff/<string:on>', 'sniff_controller', self.sniff_controller, methods=['POST'])
        self.app.add_url_rule('/api/sessions', 'list_sessions', self.list_sessions)
        self.app.add_url_rule('/api/sessions/<string:name>', 'delete_session', self.delete_session, methods=['DELETE'])
        self.app.add_url_rule('/api/sessions/<string:name>/pcap', 'get_pcap', self.get_pcap, methods=['POST'])
        self.app.add_url_rule('/api/sessions/<string:name>', 'load_session', self.load_session, methods=['POST'])
        self.app.add_url_rule('/api/node_packets', 'node_packets', self.node_packets, methods=['POST'])
        self.app.add_url_rule('/api/link_packets', 'link_packets', self.link_packets, methods=['POST'])
        self.app.add_url_rule('/api/hide', 'hide', self.hide, methods=['POST'])
        self.app.add_url_rule('/api/hidden_items', 'get_hidden_items', self.get_hidden_items)
        self.app.add_url_rule('/api/show', 'show', self.show, methods=['POST'])

    def start_app(self):
        self.app.run()

    def run_server(self):
        self.start_app()
