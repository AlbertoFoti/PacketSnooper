use crate::network_components::ipv4_packet::IPv4Packet;
use crate::network_components::mac_address::MacAddress;
use std::fmt::{Display, Formatter};

#[derive(Debug, Copy, Clone)]
pub enum EtherType {
    IPV4,
    IPV6,
}

pub struct EtherPacket {
    pub mac_addr_dst: MacAddress,
    pub mac_addr_src: MacAddress,
    pub ether_type: Option<EtherType>,
    pub payload: Vec<u8>,
}

impl EtherPacket {
    pub fn new(ether_data_in_u8: &[u8]) -> EtherPacket {
        let (mac_addr_dst, mac_addr_src, ether_type) =
            EtherPacket::decode_ethernet(&ether_data_in_u8[0..14]);
        let payload = &ether_data_in_u8[14..];
        EtherPacket {
            mac_addr_dst,
            mac_addr_src,
            ether_type,
            payload: Vec::from(payload),
        }
    }

    pub fn decode_ethernet(ether_data_in_u8: &[u8]) -> (MacAddress, MacAddress, Option<EtherType>) {
        let mac_addr_dst = MacAddress::new(&ether_data_in_u8[0..6]);
        let mac_addr_src = MacAddress::new(&ether_data_in_u8[6..12]);

        let ether_type = EtherPacket::to_ether_type(&ether_data_in_u8[12..14]);

        (mac_addr_dst, mac_addr_src, ether_type)
    }

    pub fn to_ether_type(ether_type_in_u8: &[u8]) -> Option<EtherType> {
        match ether_type_in_u8 {
            [8, 0] => return Some(EtherType::IPV4),
            [134, 221] => return Some(EtherType::IPV6),
            x => {
                return {
                    println!("{:?}", x);
                    None
                }
            }
        }
    }
}

impl Display for EtherPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ethernet : {} -> {} ",
            self.mac_addr_dst, self.mac_addr_src
        )
        .unwrap();
        match self.ether_type {
            Some(_) => {
                write!(f, "({:?}) \n", self.ether_type.unwrap())
            }
            None => {
                write!(f, "(None) \n")
            }
        }
        .unwrap();
        match self.ether_type {
            Some(EtherType::IPV4) => {
                write!(f, "{}", IPv4Packet::new(self.payload.as_slice()))
            }
            _ => {
                write!(f, "Other Protocol used at layer 3 (Unknown Protocol)")
            }
        }
    }
}
