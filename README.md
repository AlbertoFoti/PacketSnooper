# Packet-Snooper
A Rust cross-platform cli packet analyzer

## TCP/IP Architecture Support
### Layer 2 
    full-support: Ethernet
### Layer 3 (Ethernet field "EtherType". IEEE 802.3)
    full-support: IPv4, 
    identification: (IPv6, ARP).
    future support: MPLS unicast, MPLS multicast
### Layer 4 ("Protocol Type" field of L3 protocols)
    full-support: TCP, UDP
    identification: (). Others: (IGMP, ICMP)
    future support: ()
### Upper Layers
    full-support: ()
    identification: ()
    future support: ()

## Technologies Used
- Main Language: Rust
- Version Control, Team Work: Git, GitHub

## Authors
- Alberto Foti
- Samuele Giannetto
- Simone Annecchini
