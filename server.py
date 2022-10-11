from flask import Flask, jsonify

def graph_data():
    return jsonify(
    {
        "prog_nodes": [
            {
                "program": "nc",
                "tot_packets": 15
            },
            {
                "program": "programa",
                "tot_packets": 10
            }
        ],
        "ip_nodes": [
            {
                "ip": "1.456.53.145",
                "tot_packets": 15
            },
            {
                "ip": "1.665.57.15",
                "tot_packets": 10
            }
        ],
        "links": [
            {
                "ip": "1.456.53.145",
                "program": "nc",
                "in_packets": 8,
                "out_packets": 7
            },
            {
                "ip": "1.665.57.15",
                "program": "programa",
                "in_packets": 5,
                "out_packets": 5
            }
        ]
    })

def initalize_urls(app):
    app.add_url_rule('/api/graph-data', 'graph_data', graph_data)

def start_app(app):
    app.run()

def run_server():
    app = Flask(__name__)
    initalize_urls(app)
    start_app(app)
