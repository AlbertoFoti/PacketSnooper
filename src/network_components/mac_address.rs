use std::fmt::{Display, Formatter, Write};
use crate::utility;

#[derive(Debug, PartialEq)]
pub struct MacAddress {
    pub mac_raw: [u8; 6],
}

impl MacAddress {
    pub fn new(mac_in_u8: &[u8]) -> MacAddress {
        MacAddress {
            mac_raw: utility::clone_into_array(&mac_in_u8[..]),
        }
    }

    pub fn mac(&self) -> String {
        let mut mac = String::new();
        for &byte in self.mac_raw.iter() {
            write!(mac, "{:02x}:", byte).unwrap();
        }
        mac.pop();
        mac
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mac())
    }
}
