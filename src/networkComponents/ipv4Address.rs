use std::fmt::{Display, Formatter, Write};

pub struct IPv4Address {
    pub ip_raw: Vec<u8>,
}

impl IPv4Address {
    pub fn new(ip_in_u8: &[u8]) -> IPv4Address {
        IPv4Address { ip_raw: Vec::from(ip_in_u8) }
    }

    pub fn ipv4(&self) -> String {
        let mut ip = String::new();
        for &byte in self.ip_raw.iter() {
            write!(ip, "{}.", byte).unwrap();
        }
        ip.pop();
        ip
    }
}

impl Display for IPv4Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ipv4())
    }
}