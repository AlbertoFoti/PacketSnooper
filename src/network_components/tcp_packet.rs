use crate::utility;
use std::fmt::{Display, Formatter};
use crate::network_components::upper_layer_services::{known_port, print_upper_layer, UpperLayerService};

pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub upper_layer_service: UpperLayerService,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(tcp_data_in_u8: &[u8]) -> TcpPacket {
        let src_port = u16::from_be_bytes((&tcp_data_in_u8[0..2]).try_into().unwrap());
        let dst_port = u16::from_be_bytes((&tcp_data_in_u8[2..4]).try_into().unwrap());

        TcpPacket {
            src_port,
            dst_port,
            upper_layer_service: UpperLayerService::from(known_port(src_port, dst_port)),
            payload: Vec::from(&tcp_data_in_u8[4..]),
        }
    }
}

impl Display for TcpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP      ").unwrap();
        write!(
            f,
            ": {} -> {}\n",
            self.src_port,
            self.dst_port,
        ).unwrap();

        print_upper_layer(f, self.upper_layer_service).unwrap();

        write!(f, "\n > [{}]", utility::to_compact_hex(&self.payload))
    }
}
