use crate::network_components::tcp_packet::TcpPacket;
use crate::network_components::upd_packet::UdpPacket;
use std::fmt::{Display, Formatter};
use std::net::{Ipv6Addr};
use crate::utility;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Ipv6NextHeader {
    IPv6HopByHopOption,
    ICMPv4,
    IGMP,
    TCP,
    UDP,
    ICMPv6,
}

pub struct IPv6Packet {
    pub next_header: Option<Ipv6NextHeader>,
    pub ip_addr_src: Ipv6Addr,
    pub ip_addr_dst: Ipv6Addr,
    pub payload: Vec<u8>,
}

impl IPv6Packet {
    pub fn new(ipv6_data_in_u8: &[u8]) -> Self {
        IPv6Packet {
            next_header: IPv6Packet::to_protocol_type(ipv6_data_in_u8[6]),
            ip_addr_src: Ipv6Addr::from(u128::from_be_bytes((&ipv6_data_in_u8[8..24]).try_into().unwrap())),
            ip_addr_dst: Ipv6Addr::from(u128::from_be_bytes((&ipv6_data_in_u8[24..40]).try_into().unwrap())),
            payload: Vec::from(&ipv6_data_in_u8[40..]),
        }
    }

    pub fn to_protocol_type(next_header_in_u8: u8) -> Option<Ipv6NextHeader> {
        match next_header_in_u8 {
            0 => return Some(Ipv6NextHeader::IPv6HopByHopOption),
            1 => return Some(Ipv6NextHeader::ICMPv4),
            2 => return Some(Ipv6NextHeader::IGMP),
            6 => return Some(Ipv6NextHeader::TCP),
            17 => return Some(Ipv6NextHeader::UDP),
            58 => return Some(Ipv6NextHeader::ICMPv6),
            x => {
                return {
                    println!("no info on this protocol: {:?}", x);
                    None
                };
            }
        }
    }
}

impl Display for IPv6Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv6     ").unwrap();
        write!(f, ": {} -> {}\n",
            self.ip_addr_src,
            self.ip_addr_dst,
        ).unwrap();

        match self.next_header {
            Some(Ipv6NextHeader::IPv6HopByHopOption) => {
                write!(f, "IPv6Hop  : Hop by hop extension header\n").unwrap();
                match self.payload.get(0) {
                    Some(x) => {
                        let next_header = IPv6Packet::to_protocol_type(*x);
                        match next_header {
                            Some(Ipv6NextHeader::ICMPv4) => {
                                write!(f, "ICMPv4   : Unknown Details")
                            },
                            Some(Ipv6NextHeader::IGMP) => {
                                write!(f, "IGMP     : Unknown Details")
                            },
                            Some(Ipv6NextHeader::UDP) => {
                                write!(f, "{}", UdpPacket::new(self.payload.as_slice()))
                            },
                            Some(Ipv6NextHeader::TCP) => {
                                write!(f, "{}", TcpPacket::new(self.payload.as_slice()))
                            },
                            Some(Ipv6NextHeader::ICMPv6) => {
                                write!(f, "ICMPv6   : Unknown Details")
                            },
                            _ => {
                                write!(f, "Other Protocol encapsulated in IPv6 Hop by Hop Option (Unknown Protocol)")
                            }
                        }
                    },
                    None => { write!(f, "") },
                }
            },
            Some(Ipv6NextHeader::ICMPv4) => {
                write!(f, "ICMPv4   : Unknown Details")
            },
            Some(Ipv6NextHeader::IGMP) => {
                write!(f, "IGMP     : Unknown Details")
            },
            Some(Ipv6NextHeader::UDP) => {
                write!(f, "{}", UdpPacket::new(self.payload.as_slice()))
            },
            Some(Ipv6NextHeader::TCP) => {
                write!(f, "{}", TcpPacket::new(self.payload.as_slice()))
            },
            Some(Ipv6NextHeader::ICMPv6) => {
                write!(f, "ICMPv6   : Unknown Details")
            },
            _ => {
                write!(f, "Other Protocol encapsulated in IPv6 (Unknown Protocol)")
            }
        }.unwrap();

        write!(f, "\n > [{}]", utility::to_compact_hex(&self.payload))
    }
}
