mod networkComponents;
mod utility;

pub mod PacketSnooper {
    use std::io;
    use std::io::Write;
    use pcap::{Activated, Capture, Device, Packet};
    use crate::networkComponents::ethernetPacket::EtherPacket;

    pub fn print_interfaces() -> () {
        for device in Device::list().unwrap() {
            println!("------------------------------");
            println!("[{:?} ] : ", device.name);
            for address in device.addresses {
                println!("[{:?} / {:?}] : {:?}, {:?}", address.addr, address.netmask, address.dst_addr, address.broadcast_addr);
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

    fn print_packet(packet: Packet) {
        println!("------------------------");
        println!("{:?} | {:?} | {:?}", packet.header.caplen, packet.header.len, packet.header.ts.tv_sec);
        println!("{:?}", packet.data);
    }

    fn decode_packet(packet: Packet) {
        let data = packet.data;

        // ethernet header (fixed 6 B destination + 6 B source + 2 B Protocol Type = 14 B)
        let ether_packet = EtherPacket::new(&data[..]);

        println!("---------------");
        println!("{}", ether_packet);
        io::stdout().flush().unwrap();
    }
}