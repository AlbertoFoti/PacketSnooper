use crate::network_components::layer_4::tcp_packet::TcpPacket;
use crate::network_components::services_upper_layers::upper_layer_services::UpperLayerService;
use crate::network_components::tests::{IPV4_DATA_IN_U8_WITH_OPTIONS_TCP, TCP_DATA_IN_U8};

fn check_packet(tcp_packet: TcpPacket) {
    assert_eq!(tcp_packet.src_port, u16::from_be_bytes([131, 149]));
    assert_eq!(tcp_packet.dst_port, u16::from_be_bytes([1, 187]));
    assert_eq!(tcp_packet.sequence_number, u32::from_be_bytes([0, 41, 100, 18]));
    assert_eq!(tcp_packet.ack_number, u32::from_be_bytes([82, 18, 246, 2]));
    assert_eq!(tcp_packet.data_offset, 128);
    assert_eq!(tcp_packet.flags, 57);
    assert_eq!(tcp_packet.window_size, u16::from_be_bytes([214, 254]));
    assert_eq!(tcp_packet.checksum, u16::from_be_bytes([202, 113]));
    assert_eq!(tcp_packet.urgent_pointer, u16::from_be_bytes([65, 255]));
    assert_eq!(tcp_packet.options, Vec::from(&TCP_DATA_IN_U8[20..32]));
    assert_eq!(tcp_packet.payload, Vec::from(&TCP_DATA_IN_U8[32..]));
    assert_eq!(tcp_packet.upper_layer_service, UpperLayerService::HTTPS);
}

#[test]
fn new_tcp_packet_from_tcp_data() {
    let tcp_packet = TcpPacket::new(&TCP_DATA_IN_U8[..]);

    check_packet(tcp_packet);
}

#[test]
fn new_tcp_packet_from_ipv4_data() {
    let tcp_packet = TcpPacket::new(&IPV4_DATA_IN_U8_WITH_OPTIONS_TCP[20..]);

    check_packet(tcp_packet);
}
