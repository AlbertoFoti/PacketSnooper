//! # Layer 3 Protocols Support
//!
//! Module to handle `TCP/IP Layer 3`.
//!
//! ### Layer 3 (Ethernet field "EtherType". IEEE 802.3)
//!     full-support: IPv4, (IPv6), IPv6HopByHop
//!     identification: ARP
//!     future support: ()
//!

//pub mod ipv4address;

pub mod ipv4_packet;

pub mod ipv6_packet;