use crate::network_components::tests::{IPV4_DATA_IN_U8, UDP_DATA_IN_U8};
use crate::network_components::upd_packet::UdpPacket;
use crate::network_components::upper_layer_services::UpperLayerService;

fn check_packet(udp_packet: UdpPacket) {
    assert_eq!(udp_packet.src_port, [131, 149]);
    assert_eq!(udp_packet.dst_port, [1, 187]);
    assert_eq!(udp_packet.length, [0, 41]);
    assert_eq!(udp_packet.checksum, [100, 18]);
    assert_eq!(udp_packet.upper_layer_service.unwrap(), UpperLayerService::HTTPS);
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