<div align="center">

# Packet-Snooper

</div>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust-Workflow](https://github.com/XXmorpheusX/PacketSnooper/actions/workflows/rust_workflow.yml/badge.svg)](https://github.com/XXmorpheusX/PacketSnooper/actions/workflows/rust_workflow.yml)

`packet_snooper` is a cross-platform library to analyze network traffic data written using the Rust Programming Language.

It's available on Windows and UNIX-like Operating Systems such as Linux and macOS.

It was developed as part of a University project (Politecnico of Turin, Italy. "System and Device Programming". Year 2022).

<p align="center">
  <img src="img/packet_snooper_logo.png" style="alignment: center" width="200" height="200" />
</p>

## Setup / Install
### Installing dependencies
- Windows

Install WinPcap.

Download the WinPcap Developer's Pack.

Add the /Lib or /Lib/x64 folder to your LIB environment variable.

- Linux

Install the libraries and header files for the libpcap library. For example:

    On Debian based Linux: install libpcap-dev.
    On Fedora Linux: install libpcap-devel.

Note: If not running as root, you need to set capabilities like so: sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin.

- Mac OS X

libpcap should be installed on Mac OS X by default.

### Additional Info
Note: A timeout of zero may cause pcap::Capture::next to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling pcap::Capture::next in a loop.

## TCP/IP Architecture Support
### Layer 2
````
full-support: EthernetII
identification: Ethernet802.3
future support: ()
````
### Layer 3 (Ethernet field "EtherType". IEEE 802.3)
````
full-support: IPv4, (IPv6), IPv6HopByHop
identification: ARP
future support: ()
````
### Layer 4 ("Protocol Type" field of L3 protocols)
````
full-support: UDP, (TCP)
identification: (). Others: IGMP, ICMPv4, ICMPv6
future support: ()
````
### Upper Layers
````
full-support: ()
identification: FTP=20, SSH=22, SMPT=23, DNS=53, HTTP=80, POP3=110
                SFTP=115, SNMP=161, BGP=179, HTTPS=443
future support: ()
````

## Architecture Overview & Internal State Machine design
<div>
    <p align="center">
      <img src="img/architecture.jpg" width="1000" height="500" />
    </p>
    <p align="center">
      <img src="img/state_machine.jpg" width="870" height="500" />
    </p>
    <p align="center">
      <img src="img/concurrency_architecture.jpg" width="870" height="500" />
    </p>
</div>

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

<p align="center">
  <img src="img/packet_snooper_logo.png" style="alignment: center" width="500" height="500" />
</p>
