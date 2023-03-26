from flask import Flask, jsonify, request, make_response
import os

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
            else:
                print("I got a session name: {}".format(params["sessionName"]))
                folder_path = "sessions/{}".format(params["sessionName"])
                if(os.path.exists(folder_path)):
                    # session exists shouldn't overwrite it, throw an error
                    return make_response(jsonify({'message': "Session name already exists. Try another one."}), 400)
                else:
                    # create folder for session
                    os.makedirs(folder_path)
            self.packet_sniffer.stop_sniffing()
            return jsonify("Packet Sniffer Stopped")
        return jsonify("Failed")

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
        self.app.add_url_rule('/api/node_packets', 'node_packets', self.node_packets, methods=['POST'])
        self.app.add_url_rule('/api/link_packets', 'link_packets', self.link_packets, methods=['POST'])
        self.app.add_url_rule('/api/hide', 'hide', self.hide, methods=['POST'])
        self.app.add_url_rule('/api/hidden_items', 'get_hidden_items', self.get_hidden_items)
        self.app.add_url_rule('/api/show', 'show', self.show, methods=['POST'])

    def start_app(self):
        self.app.run()

    def run_server(self):
        self.start_app()
