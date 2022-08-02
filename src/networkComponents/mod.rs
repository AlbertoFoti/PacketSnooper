use std::fmt::{Display, Formatter};

pub mod MacAddress;

use MacAddress::MacAddress;

#[derive(Debug)]
pub enum EtherType {
    IPV4,
}

pub struct EtherPacket {
    mac_addr_dst: MacAddress,
    mac_addr_src: MacAddress,
    ether_type: Option<EtherType>,
    payload: Vec<u8>,
}

pub fn decode_ether_type(ether_data_in_u8: &[u8]) -> (MacAddress ,MacAddress , Option<EtherType>) {
    let mac_addr_dst = MacAddress::new(&ether_data_in_u8[0..6]);
    let mac_addr_src = MacAddress::new(&ether_data_in_u8[6..12]);

    match &ether_data_in_u8[12..14] {
        [8, 0] => return (mac_addr_dst, mac_addr_src, Some(EtherType::IPV4)),
        _ => return (mac_addr_dst, mac_addr_src, None),
    }
}