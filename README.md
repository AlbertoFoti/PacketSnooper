# Packet-Snooper
A Rust cross-platform cli packet analyzer

## TCP/IP Architecture Support
### Layer 2
    full-support: Ethernet
    identification: ()
    future support: ()
### Layer 3 (Ethernet field "EtherType". IEEE 802.3)
    full-support: IPv4, 
    identification: (IPv6, ARP).
    future support: MPLS unicast, MPLS multicast
### Layer 4 ("Protocol Type" field of L3 protocols)
    full-support: UDP, (TCP)
    identification: (). Others: (IGMP, ICMPv4)
    future support: (ICMPv6)
### Upper Layers
    full-support: ()
    identification: (FTP=20, SSH=22, SMPT=23, DNS=53, HTTP=80, POP3=110
                     SFTP=115, SNMP=161, BGP=179, HTTPS=443, )
    future support: ()

## Technologies Used
- Main Language: Rust
- Version Control, Team Work: Git, GitHub

## Authors
- Alberto Foti
- Samuele Giannetto
- Simone Annecchini
