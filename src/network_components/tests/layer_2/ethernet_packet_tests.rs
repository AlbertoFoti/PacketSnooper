use crate::EthernetPacket;
use crate::network_components::layer_2::ethernet_packet::EtherType;
use crate::network_components::layer_2::mac_address::MacAddress;
use crate::network_components::tests::layer_2::PACKET;

#[test]
fn new_ether_packet() {
    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 8, 0, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);

    assert_eq!(ethernet_packet.mac_addr_dst, MacAddress::new(&ether_data_in_u8[0..6]));
    assert_eq!(ethernet_packet.mac_addr_src, MacAddress::new(&ether_data_in_u8[6..12]));
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::IPV4);
    assert_eq!(ethernet_packet.payload, Vec::from(&ether_data_in_u8[14..]));
}

#[test]
pub fn report_data_test() {
    let ethernet_packet = EthernetPacket::from_json(PACKET).unwrap();
    assert_eq!(ethernet_packet.mac_addr_src.mac_raw, [224,185,229,48,239,152]);
    assert_eq!(ethernet_packet.mac_addr_dst.mac_raw, [116,229,249,22,238,155]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::IPV4);
    assert_eq!(ethernet_packet.payload, Vec::from([69, 0, 0, 52, 61, 246, 64, 0, 233, 6, 236, 162, 3, 93, 161, 174, 192, 168, 1, 119, 1, 187, 215, 30, 153, 191, 216, 65, 30, 224, 14, 36, 128, 16, 0, 114, 12, 83, 0, 0, 1, 1, 8, 10, 93, 226, 9, 254, 1, 227, 33, 43]));
}

#[test]
fn ether_types() {
    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 8, 0, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::IPV4);

    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 8, 6, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::ARP);

    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 134, 221, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::IPV6);
}

#[test]
fn ethernet802_3_identified() {
    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 0, 0, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::Ethernet802_3);

    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 2, 45, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::Ethernet802_3);

    let ether_data_in_u8: [u8; 75] = [224, 185, 229, 48, 239, 152, 116, 229, 249, 22, 238, 155, 0x05, 0xDC, 69, 0, 0, 61, 177, 29, 64, 0, 64, 17, 128, 107, 192, 168, 1, 90, 142, 250, 184, 42, 131, 149, 1, 187, 0, 41, 100, 18, 82, 18, 246, 2, 24, 57, 214, 254, 202, 113, 65, 255, 85, 173, 50, 221, 178, 53, 134, 231, 184, 197, 223, 157, 159, 28, 221, 181, 199, 230, 164, 142, 134];
    let ethernet_packet = EthernetPacket::new(&ether_data_in_u8[..]);
    assert_eq!(ethernet_packet.ether_type.unwrap(), EtherType::Ethernet802_3);
}


