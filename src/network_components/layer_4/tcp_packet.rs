use crate::utility;
use std::fmt::{Display, Formatter};
use crate::network_components::services_upper_layers::upper_layer_services::{known_port, print_upper_layer, UpperLayerService};

pub struct TcpPacket {
    pub src_port: u16,
    pub dst_port: u16,
    pub upper_layer_service: UpperLayerService,
    pub sequence_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(tcp_data_in_u8: &[u8]) -> TcpPacket {
        let src_port = u16::from_be_bytes((&tcp_data_in_u8[0..2]).try_into().unwrap());
        let dst_port = u16::from_be_bytes((&tcp_data_in_u8[2..4]).try_into().unwrap());
        let data_offset_nibble : usize = (((tcp_data_in_u8[12] & 0xF0) >> 4) * 4) as usize;

        TcpPacket {
            src_port,
            dst_port,
            sequence_number: u32::from_be_bytes((&tcp_data_in_u8[4..8]).try_into().unwrap()),
            ack_number: u32::from_be_bytes((&tcp_data_in_u8[8..12]).try_into().unwrap()),
            data_offset: tcp_data_in_u8[12],
            flags: tcp_data_in_u8[13],
            window_size: u16::from_be_bytes((&tcp_data_in_u8[14..16]).try_into().unwrap()),
            checksum: u16::from_be_bytes((&tcp_data_in_u8[16..18]).try_into().unwrap()),
            urgent_pointer: u16::from_be_bytes((&tcp_data_in_u8[18..20]).try_into().unwrap()),
            upper_layer_service: UpperLayerService::from(known_port(src_port, dst_port)),
            options: Vec::from(&tcp_data_in_u8[20..data_offset_nibble]),
            payload: Vec::from(&tcp_data_in_u8[data_offset_nibble..]),
        }
    }

    fn data_offset(&self) -> u8 {
        ((self.data_offset & 0xF0) >> 4) * 4
    }
}

impl Display for TcpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP      ").unwrap();
        write!(f, ": {} -> {}\n > [seq#: {}, ACK#: {}, data-offset: {}B, flags: {:#02x}, windows-size: {}, checksum: {:#04x}, urgent-pointer: {:#04x} ]\n",
               self.src_port,
               self.dst_port,
               self.sequence_number,
               self.ack_number,
               self.data_offset(),
               self.flags,
               self.window_size,
               self.checksum,
               self.urgent_pointer,
        ).unwrap();

        print_upper_layer(f, self.upper_layer_service).unwrap();

        write!(f, "\n Options > [{}]", utility::to_compact_hex(&self.options)).unwrap();
        write!(f, "\n Payload > [{}]", utility::to_compact_hex(&self.payload))
    }
}
