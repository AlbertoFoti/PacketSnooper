use crate::network_components::mac_address::MacAddress;
use crate::network_components::tests::MAC_IN_U8;

#[test]
fn new_mac_address() {
    let mac_address = MacAddress::new(MAC_IN_U8);

    assert_eq!(mac_address.mac_raw, [224, 185, 229, 48, 239, 152]);
}

#[test]
fn get_mac_address() {
    let mac_address = MacAddress::new(MAC_IN_U8);

    assert_eq!(mac_address.mac(), "e0:b9:e5:30:ef:98");
}
