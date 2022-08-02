use std::fmt::{Display, Formatter};
use crate::networkComponents::ipv4Address::IPv4Address;
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
    //pub ip_addr_src: IPv4Address,
    //pub ip_addr_dst: IPv4Address,
    //pub identification: [u8; 2],
    //pub flags: u8,
    // pub fragmentation_offset: u8,
    // pub ttl: u8,
    pub protocol_type: Option<IpProtocolType>,
    // pub header_checksum: [u8; 2],
    //pub payload: Vec<u8>,
}

impl IPv4Packet {
    pub fn new(ipv4_data_in_u8: &[u8]) -> IPv4Packet {
        //let (mac_addr_dst, mac_addr_src, ether_type) = IPv4Packet::decode_ipv4(&ipv4_data_in_u8[..]);
        let header_length = ipv4_data_in_u8[0];
        let diff_serv = ipv4_data_in_u8[1];
        let total_length: [u8; 2] = utility::clone_into_array(&ipv4_data_in_u8[2..4]);
        let protocol_type = ipv4_data_in_u8[9];
        let protocol_type = IPv4Packet::to_protocol_type(ipv4_data_in_u8[9]);
        IPv4Packet { header_length, diff_serv, total_length, protocol_type }
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
        write!(f, "IPv4 : [header-length: {}B, diff-serv: {:#04x}, tot-length: {}B, ]",
               self.header_length,
               self.diff_serv,
               self.total_length()).unwrap();
        match self.protocol_type {
            Some(et) => {
                write!(f, "({:?}) \n", self.protocol_type.unwrap())
            },
            None => { write!(f, "(None) \n") },
        }.unwrap();
        match self.protocol_type {
            Some(IpProtocolType::UDP) => {
                write!(f, "\t\t UDP : ")
            },
            Some(IpProtocolType::TCP) => {
                write!(f, "\t\t TCP : ")
            },
            _ => {
                write!(f, "\t\t Other Protocol used at layer 4 (Unknown Protocol)")
            },
        }
    }
}

