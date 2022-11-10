from flask import Flask, jsonify, request

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
        if(on.title() == "True"):
            self.packet_sniffer.sniff_packets()
            return jsonify("Packet Sniffer Started")
        elif(on.title() == "False"):
            self.packet_sniffer.stop_sniffing()
            return jsonify("Packet Sniffer Stopped")
        return jsonify("Failed")

    def node_packets(self):
        params = request.get_json()
        if(params["isIP"] == True):
            result = self.packet_sniffer.get_ip_node_packets(params["ip"])
            return jsonify(result)
        else:
            result = self.packet_sniffer.get_prog_node_packets(params["name"], params["socket"], params["fd"])
            return jsonify(result)
        return jsonify("Failed")

    def link_packets(self):
        params = request.get_json()
        result = self.packet_sniffer.get_link_packets(params["ip"], params["name"], params["socket"], params["fd"])
        return jsonify(result)

    def hide(self):
        params = request.get_json()
        if params["type"] == "program" :
            self.packet_sniffer.hide_prog_node(params["prog_name"], params["socket"], params["fd"])
        if params["type"] == "ip":
            self.packet_sniffer.hide_ip_node(params["ip"])
        if params["type"] == "link":
            print("LINK------------------------------------------------")
        return params

    def initalize_urls(self):
        self.app.add_url_rule('/api/graph-data', 'graph_data', self.graph_data)
        self.app.add_url_rule('/api/sniff/<string:on>', 'sniff_controller', self.sniff_controller, methods=['POST'])
        self.app.add_url_rule('/api/node_packets', 'node_packets', self.node_packets, methods=['POST'])
        self.app.add_url_rule('/api/link_packets', 'link_packets', self.link_packets, methods=['POST'])
        self.app.add_url_rule('/api/hide', 'hide', self.hide, methods=['POST'])

    def start_app(self):
        self.app.run()

    def run_server(self):
        self.start_app()
