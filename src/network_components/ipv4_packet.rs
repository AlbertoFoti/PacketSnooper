use crate::network_components::ipv4address::IPv4Address;
use crate::network_components::tcp_packet::TcpPacket;
use crate::network_components::upd_packet::UdpPacket;
use crate::utility;
use std::fmt::{Display, Formatter};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum IpProtocolType {
    ICMPv4,
    IGMP,
    TCP,
    UDP,
}

pub struct IPv4Packet {
    pub version: u8,
    pub header_length: u8,
    pub diff_serv: u8,
    pub total_length: [u8; 2],
    pub identification: [u8; 2],
    pub flags: u8,
    pub fragmentation_offset: u8,
    pub ttl: u8,
    pub protocol_type: Option<IpProtocolType>,
    pub header_checksum: [u8; 2],
    pub ip_addr_src: IPv4Address,
    pub ip_addr_dst: IPv4Address,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl IPv4Packet {
    pub fn new(ipv4_data_in_u8: &[u8]) -> IPv4Packet {
        let header_nibble = ipv4_data_in_u8[0] & 0x0F;
        IPv4Packet {
            version: ipv4_data_in_u8[0] >> 4,
            header_length: header_nibble,
            diff_serv: ipv4_data_in_u8[1],
            total_length: utility::clone_into_array(&ipv4_data_in_u8[2..4]),
            identification: utility::clone_into_array(&ipv4_data_in_u8[4..6]),
            flags: ipv4_data_in_u8[6],
            fragmentation_offset: ipv4_data_in_u8[7],
            ttl: ipv4_data_in_u8[8],
            protocol_type: IPv4Packet::to_protocol_type(ipv4_data_in_u8[9]),
            header_checksum: utility::clone_into_array(&ipv4_data_in_u8[10..12]),
            ip_addr_src: IPv4Address::new(&ipv4_data_in_u8[12..16]),
            ip_addr_dst: IPv4Address::new(&ipv4_data_in_u8[16..20]),
            options: IPv4Packet::options(IPv4Packet::calc_header_length(header_nibble), &ipv4_data_in_u8[..]),
            payload: IPv4Packet::payload(IPv4Packet::calc_header_length(header_nibble), &ipv4_data_in_u8[..]),
        }
    }

    pub fn calc_header_length(header_length: u8) -> u16 {
        header_length as u16 * 32 / 8
    }

    pub fn header_length(&self) -> u16 {
        self.header_length as u16 * 32 / 8
    }

    pub fn total_length(&self) -> u16 {
        utility::to_u16(&self.total_length)
    }

    pub fn payload(header_length: u16, ipv4_data_in_u8: &[u8]) -> Vec<u8> {
        Vec::from(&ipv4_data_in_u8[header_length as usize..])
    }

    pub fn options(header_length: u16, ipv4_data_in_u8: &[u8]) -> Vec<u8> {
        Vec::from(&ipv4_data_in_u8[20..header_length as usize])
    }

    pub fn to_protocol_type(protocol_type_in_u8: u8) -> Option<IpProtocolType> {
        match protocol_type_in_u8 {
            1 => return Some(IpProtocolType::ICMPv4),
            2 => return Some(IpProtocolType::IGMP),
            6 => return Some(IpProtocolType::TCP),
            17 => return Some(IpProtocolType::UDP),
            x => {
                return {
                    println!("no info on this protocol: {:?}", x);
                    None
                };
            }
        }
    }
}

impl Display for IPv4Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Blue))).unwrap();
        write!(f, "IPv4     ").unwrap();
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 255, 255)))).unwrap();

        write!(f, ": {} -> {}\n > [version: {}, header-length: {}B, diff-serv: {:#04x}, tot-length: {}B, identification: {:#04x}, flags: {:#04x}, frag-offset: {}, ttl: {}, header-checksum: {:#04x} ]\n",
            self.ip_addr_src,
            self.ip_addr_dst,
            self.version,
            self.header_length(),
            self.diff_serv,
            self.total_length(),
            utility::to_u16(&self.identification),
            self.flags,
            self.fragmentation_offset,
            self.ttl,
            utility::to_u16(&self.header_checksum),
        ).unwrap();

        match self.protocol_type {
            Some(IpProtocolType::ICMPv4) => {
                write!(f, "ICMP     : Unknown Details")
            },
            Some(IpProtocolType::IGMP) => {
                write!(f, "IGMP     : Unknown Details")
            },
            Some(IpProtocolType::UDP) => {
                write!(f, "{}", UdpPacket::new(self.payload.as_slice()))
            },
            Some(IpProtocolType::TCP) => {
                write!(f, "{}", TcpPacket::new(self.payload.as_slice()))
            },
            _ => {
                write!(f, "Other Protocol incapsulated in IPv4 (Unknown Protocol)")
            }
        }
    }
}
