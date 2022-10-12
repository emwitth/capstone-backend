from flask import Flask, jsonify

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

    def initalize_urls(self):
        self.app.add_url_rule('/api/graph-data', 'graph_data', self.graph_data)
        self.app.add_url_rule('/api/sniff/<string:on>', 'sniff_controller', self.sniff_controller, methods=['POST'])

    def start_app(self):
        self.app.run()

    def run_server(self):
        self.start_app()
