"""
Author: Mitchell Blowey

This module generates the base of every packet: the IP Header

By default, the generator will generate a packet of the specified protocol,
but still needing the source and destination IP set. 

To use:
    1. Create an IPGenerator object
    2. Set the source and destination IP addresses.
    3. Change any fields as needed.
        -Note: IP Options are not yet supported.
    4. Call pack() on the object, then append the payload.
    5. Send the returned byte object over a raw socket.
    6. Reuse the same packet as needed. After changes are made, re-call pack().

Example:
from ip_generator import IPGenerator
from constants import IPProtocol #access to protocol numbers
from raw_socket import raw_socket #easy raw socket creation and use

src_ip = '192.168.0.1'
dst_ip = '8.8.8.8'

ip_packet = IPGenerator(IPProtocol.TCP)
ip_packet.set_src_ip(src_ip)
ip_packet.set_dst_ip(dst_ip)

packet_payload = ... # creating the rest of the packet

final_packet = ip_packet.pack(len(packet_payload)) + packet_payload

rs = raw_socket()

rs.send(final_packet, dst_ip)

Design notes:
-Source and destination could be suplied in the constructor, but are not for
 the following reasons:
    1. If the pattern of supplying all important options in the constructor is used at 
       every level of the stack, then constructors at the top of the stack would be 
       far too long, as it would need to know all the options for the lower levels as
       well. This is because a constructor of one level of the network stack calls 
       the constructor of every level beneath it, thus creating the entire packet 
       skeleton at object creation.
    2. Since the packets are designed to be reused, the fields need to be able to be
       changed. The only reason there is even a function is so the IP addresses can
       be supplied as strings, as in most network modules.
"""

import ipaddress, struct, traceback, pprint
from tools import chksum, print_key_val
from constants import IPProtocol as IP

class IPGenerator:
    def __init__(self, ip_protocol):
        if type(ip_protocol) != IP:
            raise Exception('IPGenerator: Inncorrect ip_protocol format, please use the \
                IPProtocol enum in constants.py.')

        # Define all the fields on the IP header
        # with the length of each field provided to the right.
        # Care should be made to not exceed the max value of the field size,
        # or else pack() will fail.
        self.ip_version = 4                     # 4 bits
        self.ip_hdr_len = 5                     # 4 bits
        self.ip_dscp = 0                        # 6 bits
        self.ip_ecn = 0                         # 2 bits
        self.ip_total_len = 0                   # 16 bits
        self.ip_id = 1                          # 16 bits
        self.ip_flag = 2                        # 3 bits
        self.ip_frag_offset = 0                 # 13 bits
        self.ip_ttl = 255                       # 8 bits
        self.ip_protocol = ip_protocol.value    # 8 bits
        self.ip_hdr_chksum = 0                  # 16 bits
        self.ip_src_ip = 0                      # 32 bits
        self.ip_dst_ip = 0                      # 32 bits

    # Functions to set source and destination IP provided to allow the user to
    # use IP addresses as strings, with conversion done by the object methods.
    def set_src_ip(self, src_ip):
        self.ip_src_ip = int(ipaddress.IPv4Address(src_ip))

    def set_dst_ip(self, dst_ip):
        self.ip_dst_ip = int(ipaddress.IPv4Address(dst_ip))

    # Packs the IP header information into byte form. The length of the payload
    # must be provided.
    #
    # pack() does several things before returning the byte object:
    #   1. Set the length of the packet based on provided payload length.
    #   2. Set the header checksum field to 0 in preperation for checksum calculation.
    #   3. Combines fields into sizes that are multiples of 8 bits.
    #   4. Perform an initial pack, from which the checksum will be calculated.
    #   5. Increment the IP ID field, as this should be unique for each packet.
    #   6. Once the checksum is calculated, the IP header can be packed up again, this time
    #      with the checksum field filled in.
    def pack(self, payload_data_length):
        try:
            self.ip_total_len = self.ip_hdr_len * 4 + payload_data_length

            # Must be 0 for checksum calculation.
            self.ip_hdr_chksum = 0

            # combine the fields into lengths that are multiples of 8
            b0 = (self.ip_version << 4) | self.ip_hdr_len  # first byte
            b1 = (self.ip_dscp << 2) | self.ip_ecn  # second byte
            b6 = (self.ip_flag << 5) | (self.ip_frag_offset >> 8)  # sixth byte
            b7 = self.ip_frag_offset & 0xff  # seventh byte

            #initial pack to calculate check sum
            chksum_data = struct.pack('!BBHHBBBBHLL', b0, b1, self.ip_total_len, 
                                        self.ip_id, b6, b7, self.ip_ttl,
                                      self.ip_protocol, self.ip_hdr_chksum, 
                                      self.ip_src_ip, self.ip_dst_ip)

            self.ip_hdr_chksum= chksum(chksum_data)

            #incremented prior to next use
            if self.ip_id < 0xFFFF :
                self.ip_id += 1
            else:
                self.ip_id = 1

            # pack in the final ip_hdr_chksum value and return the new header
            return struct.pack('!BBHHBBBBHLL', b0, b1, self.ip_total_len, 
                                        self.ip_id, b6, b7, self.ip_ttl,
                                      self.ip_protocol, self.ip_hdr_chksum, 
                                      self.ip_src_ip, self.ip_dst_ip)

        except Exception:
            # Print generic debug information, including all IP header fields.
            traceback.print_exc()
            print('FROM IPGENERATOR')
            print_key_val(self.__dict__, starts_with='ip_')
            exit()