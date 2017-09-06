"""
Author: Mitchell Blowey

Constants for use in the fields of different headers.

This list is not complete, being only composed of the first ten protocol
options for IP headers, since it did not seem necessary to add in all possible 255 values,
most of which will never be used by this program.

I may one day reach that point where they are needed.
"""

from enum import Enum

class IPProtocol(Enum):

    
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IP_IN_IP = 4
    ST = 5
    TCP = 6
    CBT = 7
    EGP = 8
    IGP = 9

class ICMPType(Enum):
    ECHO_REPLY = 0
    DEST_UNRCHBL = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14
    
    