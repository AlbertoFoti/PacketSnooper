use std::fmt::{Display, Formatter};
use crate::network_components::layer_2::mac_address::MacAddress;
use crate::network_components::layer_3::ipv4_packet::IPv4Packet;
use crate::network_components::layer_3::ipv6_packet::IPv6Packet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum EtherType {
    Ethernet802_3,
    IPV4,
    IPV6,
    ARP,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EthernetPacket {
    pub mac_addr_dst: MacAddress,
    pub mac_addr_src: MacAddress,
    pub ether_type: Option<EtherType>,
    pub payload: Vec<u8>,
}

impl EthernetPacket {
    pub fn new(ether_data_in_u8: &[u8]) -> EthernetPacket {
        EthernetPacket {
            mac_addr_dst: MacAddress::new(&ether_data_in_u8[0..6]),
            mac_addr_src: MacAddress::new(&ether_data_in_u8[6..12]),
            ether_type: EthernetPacket::to_ether_type(&ether_data_in_u8[12..14]),
            payload: Vec::from(&ether_data_in_u8[14..]) }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(json: &str) -> Result<EthernetPacket, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn to_ether_type(ether_type_in_u8: &[u8]) -> Option<EtherType> {
        match ether_type_in_u8 {
            [x, _] if *x <= 5 => { Some(EtherType::Ethernet802_3) },
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

unsafe impl Send for EthernetPacket {}

impl Display for EthernetPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ethernet ").unwrap();
        write!(f, ": {} -> {} \n", self.mac_addr_dst, self.mac_addr_src).unwrap();

        match self.ether_type {
            Some(EtherType::Ethernet802_3) => { write!(f, "Ethernet 802.3 : Unknown Details") },
            Some(EtherType::IPV4) => { write!(f, "{}", IPv4Packet::new(self.payload.as_slice())) },
            Some(EtherType::IPV6) => { write!(f, "{}", IPv6Packet::new(self.payload.as_slice())) },
            Some(EtherType::ARP) => { write!(f, "ARP      : Unknown Details") },
            _ => { write!(f, "Other Protocol incapsulated in Ethernet frame (Unknown Protocol)") }
        }
    }
}
