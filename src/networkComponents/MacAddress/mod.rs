use std::fmt::{Display, format, Formatter, Write};

pub struct MacAddress {
    pub mac: String,
}

impl MacAddress {
    pub fn new(mac_in_u8: &[u8]) -> MacAddress {
        let mut mac = String::new();
        for &byte in mac_in_u8.iter() {
            write!(mac, "{:02x}:", byte).unwrap();
        }
        mac.pop();
        MacAddress { mac }
    }

    pub fn print(&self) {
        println!("{}", self.mac);
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mac)
    }
}