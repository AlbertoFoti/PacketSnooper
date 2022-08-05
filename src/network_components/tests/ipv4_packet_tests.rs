use std::net::Ipv4Addr;
use crate::network_components::ipv4_packet::{Ipv4ProtocolType, IPv4Packet};
use crate::network_components::tests::{IPV4_DATA_IN_U8, IPV4_DATA_IN_U8_WITH_OPTIONS};

#[test]
fn new_ipv4_packet() {
    let ipv4_packet = IPv4Packet::new(&IPV4_DATA_IN_U8[..]);

    assert_eq!(ipv4_packet.version, 4);
    assert_eq!(ipv4_packet.header_length, 5);
    assert_eq!(ipv4_packet.header_length(), 20);
    assert_eq!(ipv4_packet.diff_serv, 0);
    assert_eq!(ipv4_packet.total_length, u16::from_be_bytes([0, 61]));
    assert_eq!(ipv4_packet.identification, u16::from_be_bytes([177, 29]));
    assert_eq!(ipv4_packet.flags, 64);
    assert_eq!(ipv4_packet.fragmentation_offset, 0);
    assert_eq!(ipv4_packet.ttl, 64);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::UDP);
    assert_eq!(ipv4_packet.header_checksum, u16::from_be_bytes([128, 107]));
    assert_eq!(ipv4_packet.ip_addr_src, Ipv4Addr::new(192, 168, 1, 90));
    assert_eq!(ipv4_packet.ip_addr_dst, Ipv4Addr::new(142, 250, 184, 42));
    assert_eq!(ipv4_packet.options, Vec::new());
    assert_eq!(ipv4_packet.payload, Vec::from(&IPV4_DATA_IN_U8[20..]));
}

#[test]
fn ipv4_options() {
    let ipv4_packet = IPv4Packet::new(&IPV4_DATA_IN_U8_WITH_OPTIONS[..]);

    assert_eq!(ipv4_packet.version, 4);
    assert_eq!(ipv4_packet.header_length, 10);
    assert_eq!(ipv4_packet.header_length(), 40);
    assert_eq!(ipv4_packet.diff_serv, 0);
    assert_eq!(ipv4_packet.total_length, u16::from_be_bytes([0, 61]));
    assert_eq!(ipv4_packet.identification, u16::from_be_bytes([177, 29]));
    assert_eq!(ipv4_packet.flags, 64);
    assert_eq!(ipv4_packet.fragmentation_offset, 0);
    assert_eq!(ipv4_packet.ttl, 64);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::UDP);
    assert_eq!(ipv4_packet.header_checksum, u16::from_be_bytes([128, 107]));
    assert_eq!(ipv4_packet.ip_addr_src, Ipv4Addr::new(192, 168, 1, 90));
    assert_eq!(ipv4_packet.ip_addr_dst, Ipv4Addr::new(142, 250, 184, 42));
    assert_eq!(ipv4_packet.options, Vec::from(&IPV4_DATA_IN_U8_WITH_OPTIONS[20..40]));
    assert_eq!(ipv4_packet.payload, Vec::from(&IPV4_DATA_IN_U8_WITH_OPTIONS[40..]));
}

#[test]
fn ipv4_protocol_types() {
    let ipv4_data_in_u8_1: [u8; 61] = [69, 0, 0, 61, 177, 29, 64, 0, 64, 1, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ipv4_packet = IPv4Packet::new(&ipv4_data_in_u8_1[..]);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::ICMPv4);

    let ipv4_data_in_u8_2: [u8; 61] = [69, 0, 0, 61, 177, 29, 64, 0, 64, 2, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ipv4_packet = IPv4Packet::new(&ipv4_data_in_u8_2[..]);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::IGMP);

    let ipv4_data_in_u8_3: [u8; 61] = [69, 0, 0, 61, 177, 29, 64, 0, 64, 6, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ipv4_packet = IPv4Packet::new(&ipv4_data_in_u8_3[..]);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::TCP);

    let ipv4_data_in_u8_4: [u8; 61] = [69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ipv4_packet = IPv4Packet::new(&ipv4_data_in_u8_4[..]);
    assert_eq!(ipv4_packet.protocol_type.unwrap(), Ipv4ProtocolType::UDP);
}