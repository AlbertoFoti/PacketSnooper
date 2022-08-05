use std::fmt::Formatter;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpperLayerService {
    FTP = 20,
    SSH = 22,
    SMTP = 23,
    DNS = 53,
    HTTP = 80,
    POP3 = 110,
    SFTP = 115,
    SNMP = 161,
    BGP = 179,
    HTTPS = 443,
    UNKNOWN = 65354,
}

impl From<u16> for UpperLayerService {
    fn from(v: u16) -> UpperLayerService {
        match v {
            x if x == UpperLayerService::FTP   as u16 => UpperLayerService::FTP,
            x if x == UpperLayerService::SSH   as u16 => UpperLayerService::SSH,
            x if x == UpperLayerService::SMTP  as u16 => UpperLayerService::SMTP,
            x if x == UpperLayerService::DNS   as u16 => UpperLayerService::DNS,
            x if x == UpperLayerService::HTTP  as u16 => UpperLayerService::HTTP,
            x if x == UpperLayerService::POP3  as u16 => UpperLayerService::POP3,
            x if x == UpperLayerService::SFTP  as u16 => UpperLayerService::SFTP,
            x if x == UpperLayerService::SNMP  as u16 => UpperLayerService::SNMP,
            x if x == UpperLayerService::BGP   as u16 => UpperLayerService::BGP,
            x if x == UpperLayerService::HTTPS as u16 => UpperLayerService::HTTPS,
            65354 => UpperLayerService::UNKNOWN,
            _ => UpperLayerService::UNKNOWN
        }
    }
}

pub fn known_port(src_port: u16, dst_port: u16) -> u16 {
    if src_port < 1024 {
        src_port
    } else if dst_port < 1024 {
        dst_port
    } else {
        65354
    }
}

pub fn print_upper_layer(f: &mut Formatter<'_>, upper_layer_service: UpperLayerService) -> std::fmt::Result {
    match upper_layer_service {
        UpperLayerService::FTP   => { write!(f, "FTP     ") },
        UpperLayerService::SSH   => { write!(f, "SSH     ") },
        UpperLayerService::SMTP  => { write!(f, "SMTP    ") },
        UpperLayerService::DNS   => { write!(f, "DNS     ") },
        UpperLayerService::HTTP  => { write!(f, "HTTP    ") },
        UpperLayerService::POP3  => { write!(f, "POP3    ") },
        UpperLayerService::SFTP  => { write!(f, "SFTP    ") },
        UpperLayerService::SNMP  => { write!(f, "SNMP    ") },
        UpperLayerService::BGP   => { write!(f, "BGP     ") },
        UpperLayerService::HTTPS => { write!(f, "HTTPS   ") },
        _ => { write!(f, "Other Protocol incapsulated in TCP/UDP segment (Unknown Protocol)") }
    }.unwrap();
    write!(f, ": Protocol details unknown")
}