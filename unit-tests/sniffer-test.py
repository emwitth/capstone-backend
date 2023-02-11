import unittest
from unittest.mock import Mock, patch

# mock imports
import sys
sys.modules['psutil'] = Mock()
import psutil as psutilMock

sys.modules['data_structures.node'] = Mock()
# import data_structures.node
from data_structures.node import ProgNode as progNodeMock
from data_structures.node import ProgInfo as progInfoMock

# imports to test
import sniffer as sniffModule
from constants import *

class SnifferTest(unittest.TestCase):
    sniffer = sniffModule.PacketSniffer()
    net_connections_mock = Mock()

    def tearDown(self):
        psutilMock.reset_mock()
        progNodeMock.reset_mock()
        progInfoMock.reset_mock()

        self.sniffer.port_procs = {}

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
        processReturned = "testProcess"
        progInfoMock.return_value = processReturned

        # Act
        result = self.sniffer.associate_port_with_process(port)

        # Assert
        # psutilMock.Process().name.assert_called_once()
        progInfoMock.assert_called_with(nameReturned, port, pid)
        self.assertEqual(result, processReturned)

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
        pass




    # Helper Methods -----------------------------------------------------------
    def get_net_connections_value(self, cons):
        connections = []
        for con in cons:
            connection = Mock()
            connection.pid = con[0]
            connection.laddr.port = con[1]
            connections.append(connection)
        return connections

if __name__ == "__main__":
    unittest.main()
