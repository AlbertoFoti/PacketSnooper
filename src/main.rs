use pcap::Device;

fn main() {
    print_interfaces();
}

fn print_interfaces() -> () {
    for elem in Device::list().unwrap() {
        println!("------------------------------");
        println!("[{:?} ] : ", elem.name);
        for address in elem.addresses {
            println!("[{:?} / {:?}] : {:?}, {:?}", address.addr, address.netmask, address.dst_addr, address.broadcast_addr);
        }
        println!("Desc : {:?}", elem.desc);
    }
}
