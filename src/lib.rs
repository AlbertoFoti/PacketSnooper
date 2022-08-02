mod networkComponents;

pub mod PacketSnooper {
    use pcap::{Activated, Capture, Device, Packet};
    use crate::networkComponents;
    use crate::networkComponents::decode_ether_type;
    use crate::networkComponents::MacAddress::MacAddress;

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

    fn test_read_packets() {
        let main_device = Device::lookup().unwrap();
        let mut cap = Capture::from_device(main_device).unwrap()
            .promisc(true)
            .snaplen(5000)
            .open().unwrap();

        while let Ok(packet) = cap.next() {
            println!("received packet! {:?}", packet);
        }
    }

    fn read_packets<T: Activated>(mut capture: Capture<T>) {
        while let Ok(packet) = capture.next() {
            println!("received packet! {:?}", packet);
        }
    }

    fn decode_packet(packet: Packet) {
        let data = packet.data;

        // ethernet header (fixed 6 B destination + 6 B source + 2 B Protocol Type = 14 B)
        let (mac_addr_dst, mac_addr_src, ether_type) = decode_ether_type(&data[0..14]);

        print!("{} -> {} ", mac_addr_dst, mac_addr_src);
        match ether_type {
            Some(et) => { println!("({:?})", et) },
            None => { println!("(None)") },
        }
    }
}