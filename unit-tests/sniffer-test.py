import unittest
from unittest.mock import Mock, patch, call

# mock imports
import sys
sys.modules['psutil'] = Mock()
import psutil as psutilMock

sys.modules['data_structures.node'] = Mock()
# import data_structures.node
from data_structures.node import ProgNode as progNodeMock
from data_structures.node import IPNode as ipNodeMock
from data_structures.node import ProgInfo as progInfoMock
from data_structures.node import PacketInfo as packetInfoMock

# imports to test
import sniffer as sniffModule
from constants import *

class SnifferTest(unittest.TestCase):
    sniffer = sniffModule.PacketSniffer()
    net_connections_mock = Mock()

    def setUp(self):
        psutilMock.reset_mock()
        progNodeMock.reset_mock()
        ipNodeMock.reset_mock()
        progInfoMock.reset_mock()
        packetInfoMock.reset_mock()

        progInfoMock.side_effect = self.fake_new_prog_info

        self.sniffer.port_procs = {}
        self.sniffer.icmp_procs = {}
        self.sniffer.prog_nodes = {}
        self.sniffer.ip_nodes = {}

    def test_get_ip_hostname__seen_address__return_address(self):
        # Arrange
        ip = '172.19.168.43'
        address = 'google.com'
        self.sniffer.seen_ips[ip] = address

        # Act
        result = self.sniffer.get_ip_hostname(ip)

        # Assert
        self.assertEqual(result, address)

    def test_get_ip_hostname__new_address__return_no_hostname(self):
        # Arrange
        ip = '172.19.168.44'

        # Act
        result = self.sniffer.get_ip_hostname(ip)

        # Assert
        self.assertEqual(result, NO_HOSTNAME)

    def test_save_dns_reply_value__new_address__save_address(self):
        # Arrange
        self.sniffer.seen_ips = {}
        ip = '172.19.168.43'
        address = 'google.com'

        # Act
        self.sniffer.save_dns_reply_value(ip, address)

        # Assert
        self.assertIn(ip, self.sniffer.seen_ips)

    def test_check_if_src_or_dest__localhost_src__return__src(self):
        # Arrange
        src = self.sniffer.my_ip
        dest = '333.333.33.33'

        # Act
        result = self.sniffer.check_if_src_or_dest(src, dest)

        # Assert
        self.assertEqual(result, SRC)

    def test_check_if_src_or_dest__localhost_dest__return__dest(self):
        # Arrange
        src = '333.333.33.33'
        dest = self.sniffer.my_ip

        # Act
        result = self.sniffer.check_if_src_or_dest(src, dest)

        # Assert
        self.assertEqual(result, DEST)

    def test_associate_port_with_process__port_in_use_and_port_new__add_port_to_process_node(self):
        # Arrange
        port = 25
        pid = 1234
        psutilMock.net_connections.return_value = self.get_net_connections_value([(pid, port)])
        nameReturned = "testname"
        psutilMock.Process().name.return_value = nameReturned
        wantedProgInfo = self.fake_new_prog_info(nameReturned, port, pid)

        # Act
        result = self.sniffer.associate_port_with_process(port)

        # Assert
        # psutilMock.Process().name.assert_called_once()
        progInfoMock.assert_called_with(nameReturned, port, pid)
        self.assertEqual(result, wantedProgInfo)

    def test_associate_port_with_process__port_in_use_and_port_exists__update_process_node(self):
        # Arrange
        port = 25
        psutilMock.net_connections.return_value = self.get_net_connections_value([(0,port)])
        processMock = Mock()
        self.sniffer.port_procs[port] = processMock

        # Act
        result = self.sniffer.associate_port_with_process(port)

        # Assert
        processMock.update_timestamp.assert_called_once()
        self.assertEqual(result, processMock)

    def test_associate_port_with_process__port_not_in_use_and_port_existed__return_old_node(self):
        # Arrange
        port = 25
        psutilMock.net_connections.return_value = []
        processMock = Mock()
        self.sniffer.port_procs[port] = processMock

        # Act
        result = self.sniffer.associate_port_with_process(port)

        # Assert
        self.assertEqual(result, processMock)

    def test_associate_port_id_with_process__proc_exists_not_seen__return_new_proc(self):
        # Arrange
        id = 100
        name = 'testProcessName'
        psutilMock.process_iter.return_value = self.get_process_iters_value([(id, name)])
        wantedProgInfo = self.fake_new_prog_info(name, NO_PORT, id)

        # Act
        result = self.sniffer.associate_port_id_with_process(id)

        # Assert
        calls = [call(name, NO_PORT, id), call(NO_PROC, NO_PORT, NO_PROC)]
        progInfoMock.assert_has_calls(calls)
        self.assertEqual(result, wantedProgInfo)

    def test_associate_port_id_with_process__proc_exists_seen_previously__update_timestamp_return_old_proc(self):
        # Arrange
        id = 100
        name = 'testProcessName'
        psutilMock.process_iter.return_value = self.get_process_iters_value([(id, name)])
        wantedProgInfo = self.fake_new_prog_info(name, NO_PORT, id)
        self.sniffer.icmp_procs[id] = wantedProgInfo

        # Act
        result = self.sniffer.associate_port_id_with_process(id)

        # Assert
        wantedProgInfo.update_timestamp.assert_called_once()
        progInfoMock.assert_called_once_with(NO_PROC, NO_PORT, NO_PROC)
        self.assertEqual(result, wantedProgInfo)

    def test_associate_port_id_with_process__proc_over_seen_previously__return_old_proc(self):
        # Arrange
        id = 100
        name = 'testProcessName'
        psutilMock.process_iter.return_value = self.get_process_iters_value([])
        wantedProgInfo = self.fake_new_prog_info(name, NO_PORT, id)
        self.sniffer.icmp_procs[id] = wantedProgInfo

        # Act
        result = self.sniffer.associate_port_id_with_process(id)

        # Assert
        wantedProgInfo.update_timestamp.assert_not_called()
        progInfoMock.assert_called_once_with(NO_PROC, NO_PORT, NO_PROC)
        self.assertEqual(result, wantedProgInfo)

    def test_associate_port_id_with_process__proc_not_found__return_no_proc(self):
        # Arrange
        id = 100
        name = 'testProcessName'
        psutilMock.process_iter.return_value = self.get_process_iters_value([])
        wantedProgInfo = self.fake_new_prog_info(NO_PROC, NO_PORT, NO_PROC)

        # Act
        result = self.sniffer.associate_port_id_with_process(id)

        # Assert
        wantedProgInfo.update_timestamp.assert_not_called()
        progInfoMock.assert_called_once_with(NO_PROC, NO_PORT, NO_PROC)
        self.assertEqual(result, wantedProgInfo)

    def test_update_node_info__new_proc_and_ip__make_new_nodes(self):
        # Arrange
        src = '192.168.12.12'
        dest = '144.144.14.14'
        role = SRC
        src_name = 'source name'
        dest_name = 'dest name'
        process = FakeProgInfo('ping', 140, 44)
        packet = Mock()

        # Act
        self.sniffer.update_node_info(src, dest, role, src_name, dest_name, process, packet)

        # Assert
        progNodeMock.assert_called_once()
        ipNodeMock.assert_called_once()

    def test_update_node_info__new_proc_and_ip__make_new_nodes(self):
        # Arrange
        src = '192.168.12.12'
        dest = '144.144.14.14'
        role = SRC
        src_name = 'source name'
        dest_name = 'dest name'
        process = FakeProgInfo('ping', 140, 44)
        packet = Mock()

        # Act
        self.sniffer.update_node_info(src, dest, role, src_name, dest_name, process, packet)

        # Assert
        progNodeMock.assert_called_once()
        ipNodeMock.assert_called_once()

    def test_update_node_info__seen_proc_and_ip__get_old_nodes(self):
        # Arrange
        src = '192.168.12.12'
        dest = '144.144.14.14'
        role = SRC
        src_name = 'source name'
        dest_name = 'dest name'
        process = FakeProgInfo('ping', 140, 44)
        packet = Mock()

        progMockReturned = Mock()
        self.sniffer.prog_nodes[process] = progMockReturned

        ipMockReturned = Mock()
        self.sniffer.ip_nodes[dest] = ipMockReturned

        # Act
        self.sniffer.update_node_info(src, dest, role, src_name, dest_name, process, packet)

        # Assert
        progNodeMock.assert_not_called()
        ipNodeMock.assert_not_called()
        progMockReturned.update.assert_called_once()
        ipMockReturned.update.assert_called_once()

    @patch('sniffer.PacketSniffer.hide_link')
    def test_update_node_info__prog_node_hidden__hide_link(self, mock):
        # Arrange
        src = '192.168.12.12'
        dest = '144.144.14.14'
        role = SRC
        src_name = 'source name'
        dest_name = 'dest name'
        process = FakeProgInfo('ping', 140, 44)
        packet = Mock()

        progMockReturned = Mock()
        progMockReturned.is_hidden = True
        self.sniffer.prog_nodes[process] = progMockReturned

        ipMockReturned = Mock()
        self.sniffer.ip_nodes[dest] = ipMockReturned

        # Act
        self.sniffer.update_node_info(src, dest, role, src_name, dest_name, process, packet)

        # Assert
        progNodeMock.assert_not_called()
        ipNodeMock.assert_not_called()
        progMockReturned.update.assert_called_once()
        ipMockReturned.update.assert_called_once()
        self.sniffer.hide_link.assert_called_once()

    def test_get_graph_json__has_no_nodes__return_empty_object(self):
        # Arrange
        blankResult = {
        "links": [],
        "ip_nodes": [],
        "prog_nodes": []
        }

        # Act
        result = self.sniffer.get_graph_json()

        # Assert
        self.assertEqual(result, blankResult)

    def test_get_graph_json__has_visible_nodes__return_nodes_and_links(self):
        # Arrange
        links1 = ["link1", "link2", "link3"]
        links2 = ["link4", "link5"]
        prog1 = {'program': 'value'}
        prog2 = {'another program': 'a different value'}
        ip1 = {'ip node', 'address and stuff'}
        ip2 = {'yet another ip node', 'more stuff'}

        prog_nodes = {
            1 : Mock(),
            2 : Mock()
        }
        prog_nodes[1].make_con_list.return_value = links1
        prog_nodes[1].return_fields_for_json.return_value = prog1
        prog_nodes[1].is_hidden = False
        prog_nodes[2].make_con_list.return_value = links2
        prog_nodes[2].return_fields_for_json.return_value = prog2
        prog_nodes[2].is_hidden = False
        self.sniffer.prog_nodes = prog_nodes

        ip_nodes = {
            1 : Mock(),
            2 : Mock()
        }
        ip_nodes[1].get_info.return_value = ip1
        ip_nodes[1].is_hidden = False
        ip_nodes[2].get_info.return_value = ip2
        ip_nodes[2].is_hidden = False
        self.sniffer.ip_nodes = ip_nodes

        wantedResult = {
        'links': links1 + links2,
        'ip_nodes': [ip1, ip2],
        'prog_nodes': [prog1, prog2]
        }

        # Act
        result = self.sniffer.get_graph_json()

        # Assert
        self.assertEqual(result, wantedResult)

    def test_get_graph_json__has_hidden_nodes__skip_hidden_nodes(self):
        # Arrange
        links1 = ["link1", "link2", "link3"]
        links2 = ["link4", "link5"]
        prog1 = {'program': 'value'}
        prog2 = {'another program': 'a different value'}
        ip1 = {'ip node', 'address and stuff'}
        ip2 = {'yet another ip node', 'more stuff'}

        prog_nodes = {
            1 : Mock(),
            2 : Mock()
        }
        prog_nodes[1].make_con_list.return_value = links1
        prog_nodes[1].return_fields_for_json.return_value = prog1
        prog_nodes[1].is_hidden = False
        prog_nodes[2].make_con_list.return_value = links2
        prog_nodes[2].return_fields_for_json.return_value = prog2
        prog_nodes[2].is_hidden = True
        self.sniffer.prog_nodes = prog_nodes

        ip_nodes = {
            1 : Mock(),
            2 : Mock()
        }
        ip_nodes[1].get_info.return_value = ip1
        ip_nodes[1].is_hidden = False
        ip_nodes[2].get_info.return_value = ip2
        ip_nodes[2].is_hidden = True
        self.sniffer.ip_nodes = ip_nodes

        wantedResult = {
        'links': links1,
        'ip_nodes': [ip1],
        'prog_nodes': [prog1]
        }

        # Act
        result = self.sniffer.get_graph_json()

        # Assert
        self.assertEqual(result, wantedResult)

    def test_get_ip_node_packets__no_ip_node__return_empty_object(self):
        # Arrange
        ip = "122.222.12.21"
        wantedResult = {
            "packets": [],
            "links": []
        }

        # Act
        result = self.sniffer.get_ip_node_packets(ip)

        # Assert
        self.assertEqual(result, wantedResult)

    def test_get_ip_node_packets__ip_node_exists__return_packets_object(self):
        # Arrange
        ip = "122.222.12.21"
        wrongIp = "666.666.666.666"

        ip_nodes = {
            ip : Mock(),
            wrongIp : Mock()
        }
        goodPackets = [FakePacket("hello"), FakePacket("world")]
        ip_nodes[ip].packets = goodPackets
        badPackets = [FakePacket("olleh"), FakePacket("satan")]
        ip_nodes[wrongIp].packets = badPackets
        self.sniffer.ip_nodes = ip_nodes

        # Act
        result = self.sniffer.get_ip_node_packets(ip)

        # Assert
        for packet in goodPackets:
            self.assertIn(packet.info, result["packets"])
        for packet in badPackets:
            self.assertNotIn(packet.info, result["packets"])

    def test_get_prog_node_packets__no_prog_node__return_empty_object(self):
        # Arrange
        name = "nc"
        port = 80
        fd = 140
        wantedResult = {
            "packets": [],
            "links": []
        }

        # Act
        result = self.sniffer.get_prog_node_packets(name, port, fd)

        # Assert
        self.assertEqual(result, wantedResult)

    def test_get_prog_node_packets__seen_prog_node__return_packets_object(self):
        # Arrange
        name = "nc"
        port = 80
        fd = 140
        prog = self.fake_new_prog_info(name, port, fd)
        wrongName = "ping"
        wrongPort = 8080
        wrongFd = 160
        wrongProg = self.fake_new_prog_info(wrongName, wrongPort, wrongFd)

        prog_nodes = {
            prog: Mock(),
            wrongProg: Mock()
        }
        goodPackets = [FakePacket("hello"), FakePacket("world")]
        goodCons = ["123.123.123.123", "234.234.234.234"]
        prog_nodes[prog].packets = goodPackets
        prog_nodes[prog].make_con_list.return_value = goodCons
        badPackets = [FakePacket("olleh"), FakePacket("satan")]
        badCons = ["666.666.666.666", "776.776.776.776"]
        prog_nodes[wrongProg].packets = badPackets
        prog_nodes[wrongProg].make_con_list.return_value = badCons
        self.sniffer.prog_nodes = prog_nodes

        wantedResult = {
            "packets": ["hello", "world"],
            "links": goodCons
        }

        # Act
        result = self.sniffer.get_prog_node_packets(name, port, fd)

        # Assert
        self.assertEqual(result, wantedResult)




    # Helper Methods -----------------------------------------------------------
    def get_net_connections_value(self, cons):
        connections = []
        for con in cons:
            connection = Mock()
            connection.pid = con[0]
            connection.laddr.port = con[1]
            connections.append(connection)
        return connections

    def get_process_iters_value(self, iters):
        proc_iters = []
        for iter in iters:
            proc = Mock()
            proc.pid = iter[0]
            proc.name.return_value = iter[1]
            proc_iters.append(proc)
        return proc_iters

    def fake_new_prog_info(self, name, port, id):
        return FakeProgInfo(name, port, id)

class FakeProgInfo:
    def __init__(self, name, port, id):
        self.name = name
        self.port = port
        self.id = id
        self.fd = 0
        self.update_timestamp = Mock()

    def __eq__(self, other):
        return self.name == other.name and self.port == other.port and self.id == other.id

    def __hash__(self):
        return hash(self.name) + hash(self.port) + hash(self.id)

    def __str__(self):
        return "{} {} {}".format(self.name, self.port, self.id)

class FakePacket:
    def __init__(self, info):
        self.info = info

    def get_info(self):
        return self.info

    def __str__(self):
        return "{}".format(info)

if __name__ == "__main__":
    unittest.main()
