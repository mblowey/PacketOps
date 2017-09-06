"""
Author: Mitchell Blowey

This module generates TCP packets.

The payload of the TCP packet is supplied in the constructor.

All IP header information is taken care of by the TCPGenerator class, except IP address
information. All IP header information can still be changed.

To use: 
    1. Create TCPGenerator object.
    2. Set the source and destination IP addresses.
    3. Set the source and destination ports.
    4. Change any field as needed.
    5. Call pack().
    6. Send the returned byte object over a raw socket.
    7. Reuse the same packet as needed. After changes are made, re-call pack().

TCP Example:
from tcp_generator import TCPGenerator
from raw_socket import raw_socket

payload_data = ...

tcp_packet = TCPGenerator(payload_data)

tcp_packet.set_src_ip('127.0.0.1')
tcp_packet.set_src_port(12345)

tcp_packet.set_dst_ip('8.8.8.8')
tcp_packet.set_dst_port(21)

final_packet = tcp_packet.pack()

rs = raw_socket()
rs.send(final_packet, '8.8.8.8')
"""

from constants import IPProtocol
from tools import chksum, print_key_val
from ip_generator import IPGenerator
import struct, random, traceback, pprint

# Inhereting from the IPGenerator class for easy IP header creation
class TCPGenerator(IPGenerator):
    def __init__(self, payload):
        if type(payload) != bytes:
            raise Exception('TCPGenerator: Incorrect payload format, \
                            please pack payload into bytes.')

        # Define all the fields on the TCP header
        # with the length of each field provided to the right.
        # Care should be made to not exceed the max value of the field size,
        # or else pack() will fail.
        self.tcp_src_port = 0       # 16 bits
        self.tcp_dst_port = 0       # 16 bits
        self.tcp_sqn = 0            # 32 bits
        self.tcp_ack = 0            # 32 bits
        self.tcp_hdr_length = 5     # 4 bits, in 32 bit words
        self.tcp_reserved = 0       # 3 bits
        self.tcp_flag_ns = 0        # 1 bit
        self.tcp_flag_cwr = 0       # 1 bit
        self.tcp_flag_ece = 0       # 1 bit
        self.tcp_flag_urg = 0       # 1 bit
        self.tcp_flag_ack = 0       # 1 bit
        self.tcp_flag_psh = 0       # 1 bit; set if payload going to application
        self.tcp_flag_rst = 0       # 1 bit
        self.tcp_flag_syn = 0       # 1 bit
        self.tcp_flag_fin = 0       # 1 bit
        self.tcp_win_size = 65535   # 16 bits
        self.tcp_hdr_chksum = 0     # 16 bits
        self.tcp_urg_pntr = 0       # 16 bits
        self.tcp_opts = 0           # 0-320 bits

        # Generate the random sequence start point.
        random.seed()
        self.tcp_sqn = int(random.random() * 0x1ffffffff % 0xffffffff)

        self.payload = payload

        # Create the IP header fields by calling the IPGenerator constructor.
        super().__init__(IPProtocol.TCP)

    # See ip_generator.py for information about design decisions in regards to 
    # not requiring these fields in the constructor.
    def set_src_port(self, port):
        self.tcp_src_port = port

    def set_dst_port(self, port):
        self.tcp_dst_port = port

    # Packs the TCP header information into byte form, then appends the payload and
    # IP header.
    #
    # pack() does several things before returning the byte object:
    #   1. Set the TCP header checksum field to 0 in preperation for checksum calculation.
    #   2. Since options are not yet implemented for TCP, an error is thrown if they are set.
    #   3. Combine fields into sizes that are multiples of 8 bits.
    #   4. Create the TCP psuedo header using information from the IP header.
    #   5. Perform the rest of the initial pack, in order to calculate the checksum.
    #   6. Calculate the checksum by appending the psuedo header, TCP header information,
    #      and payload together.
    #   7. Once the checksum is calculated, the TCP header is packed up again, with
    #      the checksum field correctly filled in. 
    #   8. The IP header is then packed into byte form, and appended with the TCP header
    #      and payload.
    def pack(self):
        try:
            # Must be 0 for checksum calculation.
            self.tcp_hdr_chksum = 0

            if self.tcp_opts != 0:
                raise Exception('TCPGenerator: Error, cannot handle options')
                #change the tcp header length to match with options

            # Combine together fields smaller than a byte.
            byte13 = (self.tcp_hdr_length << 4) | self.tcp_flag_ns

            byte14 = self.tcp_flag_cwr 
            byte14 = (byte14 << 1) | self.tcp_flag_ece
            byte14 = (byte14 << 1) | self.tcp_flag_urg
            byte14 = (byte14 << 1) | self.tcp_flag_ack
            byte14 = (byte14 << 1) | self.tcp_flag_psh
            byte14 = (byte14 << 1) | self.tcp_flag_rst
            byte14 = (byte14 << 1) | self.tcp_flag_syn
            byte14 = (byte14 << 1) | self.tcp_flag_fin

            # Create the TCP psuedo header with data from the IP values.
            tcp_len = self.tcp_hdr_length * 4 + len(self.payload)
            psuedo_hdr = struct.pack('!IIBBH', self.ip_src_ip, self.ip_dst_ip, 0, 
                                        self.ip_protocol, tcp_len)

            # An intial pack of the TCP header.
            chksum_data = struct.pack('!HHIIBBHHH', self.tcp_src_port, self.tcp_dst_port,
                                        self.tcp_sqn, self.tcp_ack, byte13, byte14,
                                        self.tcp_win_size, self.tcp_hdr_chksum,
                                        self.tcp_urg_pntr)

            # The TCP checksum uses more than just the TCP header.
            self.tcp_hdr_chksum= chksum(psuedo_hdr + chksum_data + self.payload)

            tcp_data = struct.pack('!HHIIBBHHH', self.tcp_src_port, self.tcp_dst_port,
                                        self.tcp_sqn, self.tcp_ack, byte13, byte14,
                                        self.tcp_win_size, self.tcp_hdr_chksum,
                                        self.tcp_urg_pntr)

            # Pack together the IP header information.
            ip_data = super().pack(len(tcp_data+self.payload))

            return ip_data + tcp_data + self.payload

        except Exception:
            # Print generic debug information, including all IP header fields.
            traceback.print_exc()
            print('FROM TCPGENERATOR')
            print_key_val(self.__dict__, starts_with='tcp')
            exit()