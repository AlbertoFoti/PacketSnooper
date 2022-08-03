use std::fmt::Formatter;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum UpperLayerService {
    FTP,
    SSH,
    SMTP,
    DNS,
    HTTP,
    POP3,
    SFTP,
    SNMP,
    BGP,
    HTTPS,
}

pub fn to_upper_layer_service(src_port: u16, dst_port: u16) -> Option<UpperLayerService> {
    let known_port = if src_port < 1024 {
        src_port
    } else if dst_port < 1024 {
        dst_port
    } else {
        65354
    };

    match known_port {
        20 => return Some(UpperLayerService::FTP),
        22 => return Some(UpperLayerService::SSH),
        23 => return Some(UpperLayerService::SMTP),
        53 => return Some(UpperLayerService::DNS),
        80 => return Some(UpperLayerService::HTTP),
        110 => return Some(UpperLayerService::POP3),
        115 => return Some(UpperLayerService::SFTP),
        161 => return Some(UpperLayerService::SNMP),
        179 => return Some(UpperLayerService::BGP),
        443 => return Some(UpperLayerService::HTTPS),
        65354 => {
            println!("both ports are not well known");
            None
        },
        x => {
                println!("no info on this protocol running on port : {:?}", x);
                None
            }
    }
}

pub fn print_upper_layer(f: &mut Formatter<'_>, upper_layer_service: Option<UpperLayerService>) -> std::fmt::Result {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Magenta))).unwrap();
    match upper_layer_service {
        Some(UpperLayerService::FTP) => {
            write!(f, "FTP     ")
        },
        Some(UpperLayerService::SSH) => {
            write!(f, "SSH     ")
        },
        Some(UpperLayerService::SMTP) => {
            write!(f, "SMTP    ")
        },
        Some(UpperLayerService::DNS) => {
            write!(f, "DNS     ")
        },
        Some(UpperLayerService::HTTP) => {
            write!(f, "HTTP    ")
        },
        Some(UpperLayerService::POP3) => {
            write!(f, "POP3     ")
        },
        Some(UpperLayerService::SFTP) => {
            write!(f, "SFTP    ")
        },
        Some(UpperLayerService::SNMP) => {
            write!(f, "SNMP     ")
        },
        Some(UpperLayerService::BGP) => {
            write!(f, "BGP      ")
        },
        Some(UpperLayerService::HTTPS) => {
            write!(f, "HTTPS    ")
        },
        _ => {
            write!(f, "Other Protocol incapsulated in UDP segment (Unknown Protocol)")
        }
    }.unwrap();
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 255, 255)))).unwrap();
    write!(f, ": Protocol details unknown")
}