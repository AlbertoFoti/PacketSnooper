use crate::network_components::ipv4_packet::IPv4Packet;
use crate::network_components::mac_address::MacAddress;
use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EtherType {
    IPV4,
    IPV6,
    ARP,
}

pub struct EtherPacket {
    pub mac_addr_dst: MacAddress,
    pub mac_addr_src: MacAddress,
    pub ether_type: Option<EtherType>,
    pub payload: Vec<u8>,
}

impl EtherPacket {
    pub fn new(ether_data_in_u8: &[u8]) -> EtherPacket {
        EtherPacket {
            mac_addr_dst: MacAddress::new(&ether_data_in_u8[0..6]),
            mac_addr_src: MacAddress::new(&ether_data_in_u8[6..12]),
            ether_type: EtherPacket::to_ether_type(&ether_data_in_u8[12..14]),
            payload: Vec::from(&ether_data_in_u8[14..]) }
    }

    fn to_ether_type(ether_type_in_u8: &[u8]) -> Option<EtherType> {
        match ether_type_in_u8 {
            [8, 0] => return Some(EtherType::IPV4),
            [8, 6] => return Some(EtherType::ARP),
            [134, 221] => return Some(EtherType::IPV6),
            x => {
                return {
                    println!("no info on this protocol: {:?}", x);
                    None
                }
            }
        }
    }
}

impl Display for EtherPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ethernet ").unwrap();
        write!(f, ": {} -> {} \n", self.mac_addr_dst, self.mac_addr_src).unwrap();

        match self.ether_type {
            Some(EtherType::IPV4) => { write!(f, "{}", IPv4Packet::new(self.payload.as_slice())) },
            Some(EtherType::IPV6) => { write!(f, "IPv6     : Unknown Details") },
            Some(EtherType::ARP) => { write!(f, "ARP      : Unknown Details") },
            _ => { write!(f, "Other Protocol incapsulated in Ethernet frame (Unknown Protocol)") }
        }
    }
}
