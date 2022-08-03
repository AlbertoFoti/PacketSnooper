mod network_components;
mod utility;

use std::fmt::{Display, Formatter};
use crate::network_components::ethernet_packet::EtherPacket;
use pcap::{Device, Packet};
use std::io;
use std::io::Write;
use std::time::Duration;

#[derive(Debug)]
pub enum State { ConfigDevice, ConfigTimeInterval, ConfigFile, Ready, Working, Stopped, End }

pub struct PacketSnooper {
    pub state: State,
    pub current_interface: Option<Device>,
    pub time_interval: Duration,
}

impl PacketSnooper {
    pub fn new() -> PacketSnooper {
        PacketSnooper {
            state: State::ConfigDevice,
            current_interface: None,
            time_interval: Duration::from_secs(60),
        }
    }

    pub fn set_device(&mut self, device: Device) {
        self.current_interface = Option::from(device);
        self.state = State::ConfigTimeInterval;
    }

    pub fn set_time_interval(&mut self, time_interval: Duration) {
        self.time_interval = time_interval;
        self.state = State::ConfigFile;
    }
}

impl Display for PacketSnooper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Packet-Snooper: ").unwrap();
        match self.current_interface.is_some() {
            true => {
                write!(f, "[interface: {} / ", self.current_interface.as_ref().unwrap().name).unwrap();
                match self.current_interface.as_ref().unwrap().addresses.get(0).is_some() {
                    true => {
                        write!(f, "{:?}]", self.current_interface.as_ref().unwrap().addresses.get(0).unwrap().addr)
                    },
                    false => {
                        write!(f, "None")
                    }
                }
            },
            false => { write!(f, "[interface: None]") }
        }.unwrap();
        write!(f, "\nInternal State: {:?}", self.state).unwrap();
        write!(f, "\nTime inteval before report generation: {:?}", self.time_interval)
    }
}

pub fn test_simple_read_packets() {
    let mut cap = Device::lookup().unwrap().open().unwrap();

    while let Ok(packet) = cap.next() {
        decode_packet(packet);
    }
}

fn decode_packet(packet: Packet) {
    let data = packet.data;

    let ethernet_packet = EtherPacket::new(&data[..]);

    println!("---------------");
    println!("{}", ethernet_packet);
    io::stdout().flush().unwrap();
}
