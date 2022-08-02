mod network_components;
mod utility;

pub mod packet_snooper {
    use crate::network_components::ethernet_packet::EtherPacket;
    use pcap::{Device, Packet};
    use std::io;
    use std::io::Write;

    pub fn print_interfaces() -> () {
        for device in Device::list().unwrap() {
            println!("------------------------------");
            println!("[{:?} ] : ", device.name);
            for address in device.addresses {
                println!(
                    "[{:?} / {:?}] : {:?}, {:?}",
                    address.addr, address.netmask, address.dst_addr, address.broadcast_addr
                );
            }
            println!("Desc : {:?}", device.desc);
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
