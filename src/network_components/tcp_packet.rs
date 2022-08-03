use crate::utility;
use std::fmt::{Display, Formatter};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use crate::network_components::upper_layer_services::{print_upper_layer, to_upper_layer_service, UpperLayerService};

pub struct TcpPacket {
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub upper_layer_service: Option<UpperLayerService>,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(tcp_data_in_u8: &[u8]) -> TcpPacket {
        let src_port = utility::clone_into_array(&tcp_data_in_u8[0..2]);
        let dst_port = utility::clone_into_array(&tcp_data_in_u8[2..4]);
        TcpPacket {
            src_port,
            dst_port,
            upper_layer_service: to_upper_layer_service(utility::to_u16(&src_port), utility::to_u16(&dst_port)),
            payload: Vec::from(&tcp_data_in_u8[4..]),
        }
    }
}

impl Display for TcpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut stdout = StandardStream::stdout(ColorChoice::Always);
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255,140,0)))).unwrap();
        write!(f, "TCP      ").unwrap();
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 255, 255)))).unwrap();

        write!(
            f,
            ": {} -> {}\n",
            utility::to_u16(&self.src_port),
            utility::to_u16(&self.dst_port)
        ).unwrap();

        print_upper_layer(f, self.upper_layer_service).unwrap();

        write!(f, "\n > [{}]", utility::to_compact_hex(&self.payload))
    }
}
