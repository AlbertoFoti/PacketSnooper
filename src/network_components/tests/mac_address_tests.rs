use crate::network_components::mac_address::MacAddress;

#[test]
fn new_mac_address() {
    let mac_in_u8: &[u8] = &[224, 185, 229, 48, 239, 152];
    let mac_address = MacAddress::new(mac_in_u8);

    assert_eq!(mac_address.mac_raw, Vec::from([224, 185, 229, 48, 239, 152]));
}

#[test]
fn get_mac_address() {
    let mac_in_u8: &[u8] = &[224, 185, 229, 48, 239, 152];
    let mac_address = MacAddress::new(mac_in_u8);

    assert_eq!(mac_address.mac(), "e0:b9:e5:30:ef:98");
}
