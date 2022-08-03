use std::io;
use std::io::{BufRead, Write};
use std::time::Duration;
use pcap::{Device, Error};
use packet_snooper::{PacketSnooper, State};

fn main() {
    let mut packet_snooper = PacketSnooper::new();
    //packet_snooper::test_simple_read_packets();

    loop {
        clear_screen();
        println!("{}", packet_snooper);

        match packet_snooper.state {
            State::ConfigDevice => {
                print_interface_menu();
                let interface_name = get_data_from_user().expect("Error while getting interface name from user");

                match retrieve_device(interface_name.as_str()) {
                    Ok(dev) => {
                        packet_snooper.set_device(dev);
                    },
                    Err(e) => { println!("{}", e); },
                }
            }
            State::ConfigTimeInterval => {
                print_time_interval_menu();
                let time_interval: Result<u64, _> = get_data_from_user().expect("Error while getting time interval from user").parse::<u64>();
                match time_interval {
                    Ok(t) => {
                        packet_snooper.set_time_interval(Duration::from_secs(t as u64));
                    },
                    Err(e) => { println!("{}", e); },
                }
            }
            State::ConfigFile => {
                break;
            }
            State::Ready => {
                break;
            }
            _ => {
                break;
            }
        }
    }
}

fn get_data_from_user() -> Result<String, Error> {
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

fn print_interfaces() -> () {
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

fn print_main_menu() {
    println!("----------------------------------------------------------------------------");
    println!("---------------------------- Packet Snooper App ----------------------------");
}

fn print_interface_menu() {
    print_main_menu();
    print_interfaces();
    println!("------------------------");
    println!("Insert the interface name that you want to analyze :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn print_time_interval_menu() {
    print_main_menu();
    println!("Time interval selection");
    println!("------------------------");
    println!("Insert the time interval until report generation (in seconds, 60s by default) :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn clear_screen() {
    if cfg!(unix) {
        std::process::Command::new("clear").status().unwrap();
    } else if cfg!(windows) {
        std::process::Command::new("cls").status().unwrap();
    }
}
