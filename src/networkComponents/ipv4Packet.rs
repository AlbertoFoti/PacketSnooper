use std::fmt::{Display, Formatter};
use crate::networkComponents::ipv4Address::IPv4Address;
use crate::networkComponents::tcpPacket::TcpPacket;
use crate::networkComponents::updPacket::UdpPacket;
use crate::utility;

#[derive(Debug, Copy, Clone)]
pub enum IpProtocolType {
    TCP,
    UDP,
}


pub struct IPv4Packet {
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
    pub payload: Vec<u8>,
}

impl IPv4Packet {
    pub fn new(ipv4_data_in_u8: &[u8]) -> IPv4Packet {
        let (
            header_length, diff_serv, total_length, identification,
            flags, fragmentation_offset, ttl, protocol_type,
            header_checksum, ip_addr_src, ip_addr_dst, payload
        ) = IPv4Packet::decode_ipv4(&ipv4_data_in_u8[..]);
        IPv4Packet { header_length, diff_serv, total_length, identification, flags, fragmentation_offset, ttl, protocol_type, header_checksum, ip_addr_src, ip_addr_dst, payload: Vec::from(payload) }
    }

    pub fn decode_ipv4(ipv4_data_in_u8: &[u8]) -> (u8, u8, [u8;2], [u8;2], u8, u8, u8, Option<IpProtocolType>, [u8;2], IPv4Address, IPv4Address, Vec<u8>) {
        let header_length = ipv4_data_in_u8[0];
        let diff_serv = ipv4_data_in_u8[1];
        let total_length: [u8; 2] = utility::clone_into_array(&ipv4_data_in_u8[2..4]);
        let identification: [u8; 2] = utility::clone_into_array(&ipv4_data_in_u8[4..6]);
        let flags = ipv4_data_in_u8[6];
        let fragmentation_offset = ipv4_data_in_u8[7];
        let ttl = ipv4_data_in_u8[8];
        let protocol_type = ipv4_data_in_u8[9];
        let protocol_type = IPv4Packet::to_protocol_type(ipv4_data_in_u8[9]);
        let header_checksum: [u8; 2] = utility::clone_into_array(&ipv4_data_in_u8[10..12]);
        let ip_addr_src = IPv4Address::new(&ipv4_data_in_u8[12..16]);
        let ip_addr_dst = IPv4Address::new(&ipv4_data_in_u8[16..20]);
        let payload = &ipv4_data_in_u8[20..];

        ( header_length, diff_serv, total_length, identification, flags, fragmentation_offset, ttl, protocol_type, header_checksum, ip_addr_src, ip_addr_dst, Vec::from(payload) )
    }

    pub fn total_length(&self) -> u16 {
        ((self.total_length[0] as u16) << 8) | self.total_length[1] as u16
    }

    pub fn to_protocol_type(protocol_type_in_u8: u8) -> Option<IpProtocolType> {
        match protocol_type_in_u8 {
            6 => return Some(IpProtocolType::TCP),
            17 => return Some(IpProtocolType::UDP),
            x => return {
                println!("{:?}", x);
                None
            },
        }
    }
}

impl Display for IPv4Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv4 : {} -> {}  -  [header-length: {}B, diff-serv: {:#04x}, tot-length: {}B, identification: {:#04x}, flags: {:#04x}, frag-offset: {}, ttl: {}, header-checksum: {:#04x} ] ",
               self.ip_addr_src,
               self.ip_addr_dst,
               self.header_length,
               self.diff_serv,
               self.total_length(),
               utility::to_u16(&self.identification),
               self.flags,
               self.fragmentation_offset,
               self.ttl,
               utility::to_u16(&self.header_checksum),
               ).unwrap();
        match self.protocol_type {
            Some(et) => {
                write!(f, "({:?}) \n", self.protocol_type.unwrap())
            },
            None => { write!(f, "(None) \n") },
        }.unwrap();
        match self.protocol_type {
            Some(IpProtocolType::UDP) => {
                write!(f, "{}", UdpPacket::new(self.payload.as_slice()))
            },
            Some(IpProtocolType::TCP) => {
                write!(f, "{}", TcpPacket::new(self.payload.as_slice()))
            },
            _ => {
                write!(f, "Other Protocol used at layer 4 (Unknown Protocol)")
            },
        }
    }
}

