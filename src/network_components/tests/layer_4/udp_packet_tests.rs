use crate::network_components::layer_4::upd_packet::UdpPacket;
use crate::network_components::services_upper_layers::upper_layer_services::UpperLayerService;
use crate::network_components::tests::{IPV4_DATA_IN_U8, UDP_DATA_IN_U8};

fn check_packet(udp_packet: UdpPacket) {
    assert_eq!(udp_packet.src_port, u16::from_be_bytes([131, 149]));
    assert_eq!(udp_packet.dst_port, u16::from_be_bytes([1, 187]));
    assert_eq!(udp_packet.length, u16::from_be_bytes([0, 41]));
    assert_eq!(udp_packet.checksum, u16::from_be_bytes([100, 18]));
    assert_eq!(udp_packet.upper_layer_service, UpperLayerService::HTTPS);
}

#[test]
fn new_udp_packet_from_udp_data() {
    let udp_packet = UdpPacket::new(&UDP_DATA_IN_U8[..]);

    check_packet(udp_packet);
}

#[test]
fn new_udp_packet_from_ipv4_data() {
    let udp_packet = UdpPacket::new(&IPV4_DATA_IN_U8[20..]);

    check_packet(udp_packet);
}