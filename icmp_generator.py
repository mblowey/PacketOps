"""
Author: Mitchell Blowey

This module generates ICMP packets.
It also includes a Ping class, for easy pinging.

The type of ICMP message, payload, and any necessary codes are supplied in the constructor.

All IP Header information is taken care of by the ICMPGenerator class, except IP address 
information. All IP header information can still be changed.

To use:
    1. Create ICMPGenerator object.
    2. Set the source and destination IP addresses.
    3. Change any fields as needed.
    4. Call pack() on the object.
    5. Send the returned byte object over a raw packet.
    6. Reuse the same packet as needed. After changes are made re-call pack().

ICMP Example:
from icmp_generator import ICMPGenerator
from constants import ICMPType
from raw_socket import raw_socket
import random

src_ip = '192.168.0.1'
dst_ip = '8.8.8.8'

#creates a simple ping request
icmp_packet = ICMPGenerator(ICMPType.ECHO_REQUEST, b'abcdefgh')
icmp_packet.set_src_ip(src_ip)
icmp_packet.set_dst_ip(dst_ip)

# Set the id field of the echo request.
icmp_packet.icmp_opt = random.randrange(0xffff) << 16

final_packet = icmp_packet.pack()

rs = raw_socket()

rs.send(final_packet, dst_ip)

# After each ping, the sequence number needs to be incremented.
icmp_packet.icmp_opt += 1
"""

import struct, random
from constants import ICMPType, IPProtocol
from tools import chksum
from ip_generator import IPGenerator

# Inhereting from the IPGenerator class for easy IP header creation
class ICMPGenerator(IPGenerator):
    def __init__(self, type_, payload, code=0):
        if type(type_) != ICMPType:
            raise Exception('ICMPGenerator: incorrect type format, ' +
                            'please use the ICMPGenerator enum found in constants.py.')
        elif type(payload) != bytes:
            raise Exception('ICMPGenerator: Incorrect payload format, ' +
                            'please pack payload into bytes.')

        # Define all the fields on the ICMP header
        # with the length of each field provided to the right.
        # Care should be made to not exceed the max value of the field size,
        # or else pack() will fail.
        self.icmp_type = type_.value #8 bits
        self.icmp_code = code        #8 bits
        self.icmp_hdr_chksum = 0     #16 bits
        self.icmp_opt = 0            #32 bits

        self.payload = payload

        # Create the IP header fields by calling the IPGenerator constructor.
        super().__init__(IPProtocol.ICMP)

    # Packs the ICMP header information into byte form, then appends the payload.
    #
    # pack() does several things before returning the byte object:
    #   1. Set the ICMP header checksum field to 0 in preperation for checksum calculation.
    #   2. Perform an initial pack, from which the checksum will be calculated.
    #   3. Repacks the structure with the freshly calculated checksum.
    #   4. Generates the IP Header for the packet by calling IPGenerator.pack().
    #
    #   Finally, pack() returns the IP header with the ICMP data appended.
    def pack(self):
        # Must be 0 for checksum calculation.
        self.icmp_hdr_chksum = 0

        chksum_data = struct.pack('!BBHI', self.icmp_type, self.icmp_code, 
                                    self.icmp_hdr_chksum, self.icmp_opt) + self.payload

        self.icmp_hdr_chksum = chksum(chksum_data)

        icmp_data = struct.pack('!BBHI', self.icmp_type, self.icmp_code, 
                                    self.icmp_hdr_chksum, self.icmp_opt) + self.payload

        ip_data = super().pack(len(icmp_data))

        return ip_data + icmp_data

"""
Ping Example:
from icmp_generator import Ping
from raw_socket import raw_socket

src_ip = '192.168.0.1'
dst_ip = '8.8.8.8'

# All ID and sequence values are handled by the Ping class automatically.
ping_packet = Ping()
ping_packet.set_src_ip(src_ip)
ping_packet.set_dst_ip(dst_ip)

rs = raw_socket()
rs.send(ping_packet.pack(), dst_ip)
""" 
class Ping(ICMPGenerator):
    def __init__(self, message=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        if (len(message) % 2 != 0):
            message += b' '
        super().__init__(ICMPType.ECHO_REQUEST, message)

        #set the ping id to a random value
        random.seed()
        id_ = random.randrange(0xffff)

        self.icmp_opt = id_ << 16

    def pack(self):
        #increment the sequence number
        self.icmp_opt += 1

        return super().pack()
