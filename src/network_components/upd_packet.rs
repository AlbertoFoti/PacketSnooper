use std::fmt::{Display, Formatter};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use crate::utility;

pub struct UdpPacket {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(udp_data_in_u8: &[u8]) -> UdpPacket {
        let (src_port, dst_port, payload) = UdpPacket::decode_udp(&udp_data_in_u8[..]);
        UdpPacket {
            src_port,
            dst_port,
            payload,
        }
    }

    pub fn decode_udp(udp_data_in_u8: &[u8]) -> ([u8; 2], [u8; 2], Vec<u8>) {
        let src_port = utility::clone_into_array(&udp_data_in_u8[0..2]);
        let dst_port = utility::clone_into_array(&udp_data_in_u8[2..4]);
        let payload = &udp_data_in_u8[4..];

        (src_port, dst_port, Vec::from(payload))
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255,140,0)))).unwrap();
        write!(f, "UDP      ").unwrap();
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 255, 255)))).unwrap();
        write!(
            f,
            ": {} -> {}",
            utility::to_u16(&self.src_port),
            utility::to_u16(&self.dst_port)
        )
    }
}
