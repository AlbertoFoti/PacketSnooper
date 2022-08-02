use crate::utility;
use std::fmt::{Display, Formatter};

pub struct TcpPacket {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(tcp_data_in_u8: &[u8]) -> TcpPacket {
        let (src_port, dst_port, payload) = TcpPacket::decode_tcp(&tcp_data_in_u8[..]);
        TcpPacket {
            src_port,
            dst_port,
            payload,
        }
    }

    pub fn decode_tcp(tcp_data_in_u8: &[u8]) -> ([u8; 2], [u8; 2], Vec<u8>) {
        let src_port = utility::clone_into_array(&tcp_data_in_u8[0..2]);
        let dst_port = utility::clone_into_array(&tcp_data_in_u8[2..4]);
        let payload = &tcp_data_in_u8[4..];

        (src_port, dst_port, Vec::from(payload))
    }
}

impl Display for TcpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TCP: {} -> {}",
            utility::to_u16(&self.src_port),
            utility::to_u16(&self.dst_port)
        )
    }
}
