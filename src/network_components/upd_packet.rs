use std::fmt::{Display, Formatter};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use crate::network_components::upper_layer_services::{known_port, print_upper_layer, UpperLayerService};
use crate::utility;

pub struct UdpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub upper_layer_service: UpperLayerService,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(udp_data_in_u8: &[u8]) -> UdpPacket {
        let src_port = u16::from_be_bytes((&udp_data_in_u8[0..2]).try_into().unwrap());
        let dst_port = u16::from_be_bytes((&udp_data_in_u8[2..4]).try_into().unwrap());

        UdpPacket {
            src_port,
            dst_port,
            length: u16::from_be_bytes((&udp_data_in_u8[4..6]).try_into().unwrap()),
            checksum: u16::from_be_bytes((&udp_data_in_u8[6..8]).try_into().unwrap()),
            upper_layer_service: UpperLayerService::from(known_port(src_port, dst_port)),
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
            self.src_port,
            self.dst_port,
            self.length,
            self.checksum,
        ).unwrap();

        print_upper_layer(f, self.upper_layer_service).unwrap();

        write!(f, "\n > [{}]", utility::to_compact_hex(&self.payload))
    }
}
