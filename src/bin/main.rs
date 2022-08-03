use std::io;
use std::io::{BufRead, Write};
use pcap::{Device, Error};
use packet_snooper::packet_snooper::{PacketSnooper, print_interfaces};

fn main() {
    let mut packet_snooper = PacketSnooper::new();
    //packet_snooper::test_simple_read_packets();

    loop {
        print_interface_menu();
        let interface_name = get_interface_from_user().expect("Error while getting interface name from user");

        match retrieve_device(interface_name.as_str()) {
            Ok(dev) => {
                packet_snooper.set_device(dev);
            },
            Err(e) => { println!("{}", e); },
        }

        println!("{}", packet_snooper);

        break;
    }
}

fn print_interface_menu() {
    println!("----------------------------------------------------------------------------");
    println!("---------------------------- Packet Snooper App ----------------------------");
    print_interfaces();
    println!("------------------------");
    println!("Insert the interface name that you want to analyze :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn get_interface_from_user() -> Result<String, Error> {
    let mut buffer = String::new();
    io::stdin().lock().read_line(&mut buffer)?;
    buffer.pop();
    Ok(buffer)
}

fn retrieve_device(interface_name: &str) -> Result<Device, &'static str> {
    for device in Device::list().unwrap() {
        if interface_name == device.name {
            return Ok(device);
        }
    }
    Err("unable to find device with the specified interface name")
}
