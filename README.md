# PacketOps
## A python library for easily creating different types of network packets.

For any protocol of the network stack, the given generator will create the complete skeleton of the packet, filling in most of the fields.

## Currently Supported Protocols
IP, ICMP, and TCP (Options for IP and TCP are not yet supported, only basic headers.)

## Examples

Creating packets is incredibly easy. 

Here is a simple IP header packet with no payload.
```python
from ip_generator import IPGenerator
from constants import IPProtocol # Access to protocol numbers
from raw_socket import raw_socket # Easy raw socket creation and use

src_ip = '192.168.0.1'
dst_ip = '8.8.8.8'

ip_packet = IPGenerator(IPProtocol.TCP)
ip_packet.set_src_ip(src_ip)
ip_packet.set_dst_ip(dst_ip)

packet_payload = b''

# The packet in byte format, ready to be sent on a raw socket.
final_packet = ip_packet.pack(len(packet_payload)) + packet_payload

rs = raw_socket()

rs.send(final_packet, dst_ip)
```

The next two examples are two different ways to send an echo request (Ping); the first creates a basic ICMP packet and configures it, the second uses the built in Ping packet creator.
```python
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
```

And the Ping Generator:
```python
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
```

Basic TCP packets can also be created. Here is a syn packet, being sent to start the TCP handshake.
```python3
from tcp_generator import TCPGenerator
from raw_socket import raw_socket

payload_data = b''

src_ip = '192.168.0.1'
dst_ip = '8.8.8.8'

tcp_packet = TCPGenerator(payload_data)

tcp_packet.set_src_ip(src_ip)
tcp_packet.set_src_port(12345)

tcp_packet.set_dst_ip(dst_ip)
tcp_packet.set_dst_port(21)

# Set the SYN flag
tcp_packet.tcp_flag_syn = 1

final_packet = tcp_packet.pack()

rs = raw_socket()
rs.send(final_packet, src_ip)
```

## Planned Updates
The next few features planned are:
1. UDP Packets
2. A class to abstract away and automatically handle TCP conversations
3. Better IP and TCP option handling
