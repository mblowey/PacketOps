"""
Author: Mitchell Blowey

A class to easily create and use raw sockets on a linux platform.

Must be run as root to work.
"""

import socket

class raw_socket:
    def __init__(self):
        # Two sockets are created:
        # The first uses socket.IPPROTO_RAW in order to send IP packets.
        # The second uses socket.IPPROTO_ICMP in order to receive IP packets,
        # since socket.IPPROTO_RAW cannot receive IP packets.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    def send(self, data, dst_ip):
        if type(data) != bytes:
            raise Exception('IPGenerator: Incorrect data format, please pack data into bytes.')

        return self.socket.sendto(data, (dst_ip, 0))

    def receive(self):
        return self.receive_socket.recv(65535)