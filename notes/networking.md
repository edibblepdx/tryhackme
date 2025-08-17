# Networking Concepts

## OSI Model
> Conceptual Model

7. Application Layer  

Providing services and interfaces to applications
> HTTP, FTP, DNS, POP3, SMTP, IMAP

6. Presentation Layer  

Data encoding, encryption, and compression
> Unicode, MIME, JPEG, PNG, MPEG

5. Session Layer  

Establishing, maintaining, and synchronising sessions
> NFS, RPC

4. Transport Layer  

End-to-end communication and data segmentation
> UDP, TCP

3. Network Layer  

Logical addressing and routing between networks
> IP, ICMP, IPSec

2. Data Link Layer  

Reliable data transfer between adjacent nodes
> Ethernet (802.3), WiFi (802.11)

1. Physical Layer  

Physical data transmission media
> Electrical, optical, and wireless signals

## TCP/IP Model
> Real Model

4. Application Layer  

The OSI model layers 5, 6, 7.
> HTTP, HTTPS, FTP, POP3, SMTP, IMAP, Telnet, SSH,

3. Transport Layer  

The OSI model layer 4.
> UDP, TCP

3. Internet Layer  

The OSI model layer 3
> IP, ICMP, IPSec

2. Link Layer  

The OSI model layer 2
> Ethernet (802.3), WiFi (802.11)

1. Physical Layer  

The OSI model layer 1

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
