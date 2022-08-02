use std::fmt::{Display, Formatter};

pub struct UdpPacket {
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(udp_data_in_u8: &[u8]) -> UdpPacket {
        let payload = UdpPacket::decode_udp(&udp_data_in_u8[..]);
        UdpPacket { payload }
    }

    pub fn decode_udp(udp_data_in_u8: &[u8]) -> Vec<u8> {
        let payload = &udp_data_in_u8[..];

        Vec::from(payload)
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP : ")
    }
}
