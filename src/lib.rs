mod network_components;
mod utility;

pub mod packet_snooper {
    use std::fmt::{Display, Formatter};
    use crate::network_components::ethernet_packet::EtherPacket;
    use pcap::{Device, Packet};
    use std::io;
    use std::io::Write;

    pub struct PacketSnooper {
        pub current_interface: Option<Device>,
    }

    impl PacketSnooper {
        pub fn new() -> PacketSnooper {
            PacketSnooper {
                current_interface: None,
            }
        }

        pub fn set_device(&mut self, device: Device) {
            self.current_interface = Option::from(device);
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
            }
        }
    }

    pub fn print_interfaces() -> () {
        println!("List of available interfaces: ");
        for device in Device::list().unwrap() {
            print!("[{:?} ] : ", device.name);
            if device.addresses.is_empty() {
                println!();
                break
            };
            for address in device.addresses {
                println!(
                    "[{:?} / {:?}]",
                    address.addr, address.netmask
                );
                break;
            }
        }
    }

    pub fn test_simple_read_packets() {
        let mut cap = Device::lookup().unwrap().open().unwrap();

        while let Ok(packet) = cap.next() {
            //print_packet(packet);
            decode_packet(packet);
        }
    }

    /*
    fn print_packet(packet: Packet) {
        println!("------------------------");
        println!("{:?} | {:?} | {:?}", packet.header.caplen, packet.header.len, packet.header.ts.tv_sec);
        println!("{:?}", packet.data);
    }
    */

    fn decode_packet(packet: Packet) {
        let data = packet.data;

        let ethernet_packet = EtherPacket::new(&data[..]);

        println!("---------------");
        println!("{}", ethernet_packet);
        io::stdout().flush().unwrap();
    }
}
