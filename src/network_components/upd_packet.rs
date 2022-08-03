use std::fmt::{Display, Formatter};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use crate::network_components::upper_layer_services::{print_upper_layer, to_upper_layer_service, UpperLayerService};
use crate::utility;

pub struct UdpPacket {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub length: [u8; 2],
    pub checksum: [u8; 2],
    pub upper_layer_service: Option<UpperLayerService>,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(udp_data_in_u8: &[u8]) -> UdpPacket {
        let src_port = utility::clone_into_array(&udp_data_in_u8[0..2]);
        let dst_port = utility::clone_into_array(&udp_data_in_u8[2..4]);
        UdpPacket {
            src_port,
            dst_port,
            length: utility::clone_into_array(&udp_data_in_u8[4..6]),
            checksum: utility::clone_into_array(&udp_data_in_u8[6..8]),
            upper_layer_service: to_upper_layer_service(utility::to_u16(&src_port), utility::to_u16(&dst_port)),
            payload: Vec::from(&udp_data_in_u8[8..]),
        }
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
            ": {} -> {}  - [length: {}, checksum: {:#04x}]\n",
            utility::to_u16(&self.src_port),
            utility::to_u16(&self.dst_port),
            utility::to_u16(&self.length),
            utility::to_u16(&self.checksum),
        ).unwrap();

        print_upper_layer(f, self.upper_layer_service).unwrap();

        write!(f, "\n > [{}]", utility::to_compact_hex(&self.payload))
    }
}
