# Packet-Snooper
A Rust cross-platform cli packet analyzer

## TCP/IP Architecture Support
### Layer 2
    full-support: EthernetII
    identification: Ethernet802.3
    future support: ()
### Layer 3 (Ethernet field "EtherType". IEEE 802.3)
    full-support: IPv4, (IPv6), IPv6HopByHop
    identification: ARP
    future support: ()
### Layer 4 ("Protocol Type" field of L3 protocols)
    full-support: UDP, (TCP)
    identification: (). Others: IGMP, ICMPv4, ICMPv6
    future support: ()
### Upper Layers
    full-support: ()
    identification: FTP=20, SSH=22, SMPT=23, DNS=53, HTTP=80, POP3=110
                    SFTP=115, SNMP=161, BGP=179, HTTPS=443
    future support: ()

## Architecture Overview
![This is an image](img/architecture.jpg)

## Internal State Machine design
![This is an image](img/statemachine.jpg)

## Technologies Used
- Main programming Language: Rust
- Version Control, Team Work: Git, GitHub

## Libraries (rust crates) used
- pcap
- serde
- serde_json

## Authors
- Alberto Foti
- Samuele Giannetto
- Simone Annecchini
