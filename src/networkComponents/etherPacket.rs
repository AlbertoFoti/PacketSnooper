use std::fmt::{Display, Formatter, Write};
use crate::networkComponents::macAddress::MacAddress;

#[derive(Debug, Copy, Clone)]
pub enum EtherType {
    IPV4,
}

pub struct EtherPacket {
    pub mac_addr_dst: MacAddress,
    pub mac_addr_src: MacAddress,
    pub ether_type: Option<EtherType>,
    pub payload: Vec<u8>,
}

impl EtherPacket {
    pub fn new(ether_data_in_u8: &[u8]) -> EtherPacket {
        let (mac_addr_dst, mac_addr_src, ether_type) = EtherPacket::decode_ether_type(&ether_data_in_u8[0..14]);
        let payload = &ether_data_in_u8[14..];
        EtherPacket { mac_addr_dst, mac_addr_src, ether_type, payload: Vec::from(payload) }
    }

    pub fn decode_ether_type(ether_data_in_u8: &[u8]) -> (MacAddress ,MacAddress , Option<EtherType>) {
        let mac_addr_dst = MacAddress::new(&ether_data_in_u8[0..6]);
        let mac_addr_src = MacAddress::new(&ether_data_in_u8[6..12]);

        match &ether_data_in_u8[12..14] {
            [8, 0] => return (mac_addr_dst, mac_addr_src, Some(EtherType::IPV4)),
            _ => return (mac_addr_dst, mac_addr_src, None),
        }
    }
}

impl Display for EtherPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ethernet : {} -> {} ", self.mac_addr_dst, self.mac_addr_src);
        match self.ether_type {
            Some(et) => { write!(f, "({:?})", self.ether_type.unwrap()) },
            None => { write!(f, "(None)") },
        }
    }
}