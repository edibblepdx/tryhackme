# Networking Concepts

## OSI Model
> Conceptual Model

#### 7. Application Layer  

Providing services and interfaces to applications
> HTTP, FTP, DNS, POP3, SMTP, IMAP

#### 6. Presentation Layer  

Data encoding, encryption, and compression
> Unicode, MIME, JPEG, PNG, MPEG

#### 5. Session Layer  

Establishing, maintaining, and synchronising sessions
> NFS, RPC

#### 4. Transport Layer  

End-to-end communication and data segmentation
> UDP, TCP

#### 3. Network Layer  

Logical addressing and routing between networks
> IP, ICMP, IPSec

#### 2. Data Link Layer  

Reliable data transfer between adjacent nodes
> Ethernet (802.3), WiFi (802.11)

#### 1. Physical Layer  

Physical data transmission media
> Electrical, optical, and wireless signals

## TCP/IP Model
> Real Model

#### 4. Application Layer  

The OSI model layers 5, 6, 7.
> HTTP, HTTPS, FTP, POP3, SMTP, IMAP, Telnet, SSH,

#### 3. Transport Layer  

The OSI model layer 4.
> UDP, TCP

#### 2. Internet Layer  

The OSI model layer 3
> IP, ICMP, IPSec

#### 1. Link Layer  

The OSI model layer 2
> Ethernet (802.3), WiFi (802.11)

## IP Addresses and Subnets

0 and 255 are reserved for the network and broadcast addresses, respectively. In other words, `192.168.1.0` is the network address, while `192.168.1.255` is the broadcast address.  

- Subnet masks out bits.  
- CIDER notation is a compact representation of an IP address and it's associated network mask.  

RFC 1918 defines the following three ranges of private IP addresses:  

- 10.0.0.0 - 10.255.255.255 (10/8)
- 172.16.0.0 - 172.31.255.255 (172.16/12)
- 192.168.0.0 - 192.168.255.255 (192.168/16)

## UDP and TCP

#### UDP (User Datagram Protocol)

- connectionless
- no guaranteed delivery
- no guaranteed order of delivery

#### TCP (Transmission Control Protocol)

- connection-oriented
- three way handshake: SYN, SYN-ACK, ACK

## Encapsulation

1. Application data
2. At the transport layer, add a TCP or UDP header to create a __TCP segment__ or a __UDP datagram__
3. At the network layer, IP header to get an __IP packet__
4. At the link layer, add appropriate header and trailer to get a WiFi or Ethernet frame

# Networking Essentials

## DHCP: Dynamic Host Configuration Protocol

Whenever we want to access a network, at the very least, we need to configure the following:  

- IP address along with subnet mask  
- Router (or gateway)  
- DNS server  

To resolve IP address conflicts, we use DHCP. DHCP is an application-level protocol that relies on UDP; the server listens on UDP port 67, and the client sends from UDP port 68.  

1. __DHCP Discover__: The client broadcasts a DHCPDISCOVER message seeking the local DHCP server if one exists.  

2. __DHCP Offer__: The server responds with a DHCPOFFER message with an IP address available for the client to accept.  

3. __DHCP Request__: The client responds with a DHCPREQUEST message to indicate that it has accepted the offered IP.  

4. __DHCP Acknowledge__: The server responds with a DHCPACK message to confirm that the offered IP address is now assigned to this client.  

## ARP: Bridging Layer 3 Addressing to Layer 2 Addressing

Address Resolution Protocol (ARP) makes it possible to find the MAC address of another device on the Ethernet.  

Host 1 sends an ARP request asking host 2 to respond with its MAC address. The ARP Request is sent from the MAC address of the requester to the broadcast MAC address, `ff:ff:ff:ff:ff:ff`. The ARP Reply returns with the MAC address of host 2.  

An ARP Request or ARP Reply is not encapsulated within a UDP or even IP packet; it is encapsulated directly within an Ethernet frame.  

ARP is considered layer 2 because it deals with MAC addresses.  

## ICMP: Troubleshooting Networks

Internet Control Message Protocol (ICMP) is mainly used for network diagnostics and error reporting.  

- `ping`: uses ICMP to test connectivity to a target system and measures the round-trip time (RTT).  

- `traceroute`: uses ICMP to discover the route from your host to the target.  

#### Ping

The `ping` command sends an ICMP Echo Request (ICMP Type 8). The computer on the receiving end responds with an ICMP Echo Reply (ICMP Type 0).

#### Traceroute

The Internet protocol has a field called Time-to-Live (TTL) that indicates the maximum number of routers a packet can travel through before it is dropped. The router decrements the packet’s TTL by one before it sends it across. When the TTL reaches zero, the router drops the packet and sends an ICMP Time Exceeded message (ICMP Type 11).  

`traceroute` utilizes the IP protocol's time to live (TTL) field and attempts  to elicit an ICMP TIME_EXCEEDED response from each gateway along the path to the host.  

## Routing

- __OSPF (Open Shortest Path First)__: OSPF is a routing protocol that allows routers to share information about the network topology and calculate the most efficient paths for data transmission. It does this by having routers exchange updates about the state of their connected links and networks. This way, each router has a complete map of the network and can determine the best routes to reach any destination.

- __EIGRP (Enhanced Interior Gateway Routing Protocol)__: EIGRP is a Cisco proprietary routing protocol that combines aspects of different routing algorithms. It allows routers to share information about the networks they can reach and the cost (like bandwidth or delay) associated with those routes. Routers then use this information to choose the most efficient paths for data transmission.

- __BGP (Border Gateway Protocol)__: BGP is the primary routing protocol used on the Internet. It allows different networks (like those of Internet Service Providers) to exchange routing information and establish paths for data to travel between these networks. BGP helps ensure data can be routed efficiently across the Internet, even when traversing multiple networks.

- __RIP (Routing Information Protocol)__: RIP is a simple routing protocol often used in small networks. Routers running RIP share information about the networks they can reach and the number of hops (routers) required to get there. As a result, each router builds a routing table based on this information, choosing the routes with the fewest hops to reach each destination.

## NAT: Network Address Transmission

Use one (technically two) __public IP addresses__ to provide internet access to many __private IP addresses__.  

The router maintains a table that maps the internal IP address and port number with its external IP address and port number.  
