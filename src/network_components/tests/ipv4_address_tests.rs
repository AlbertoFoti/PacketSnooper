use crate::network_components::ipv4address::IPv4Address;
use crate::network_components::tests::IPV4_IN_U8;

#[test]
fn new_ipv4_address() {
    let ipv4_address = IPv4Address::new(IPV4_IN_U8);

    assert_eq!(ipv4_address.ip_raw, Vec::from([192, 168, 1, 76]));
}

#[test]
fn get_mac_address() {
    let ipv4_address = IPv4Address::new(IPV4_IN_U8);

    assert_eq!(ipv4_address.ipv4(), "192.168.1.76");
}