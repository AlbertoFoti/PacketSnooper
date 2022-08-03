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
                    Err(e) => { println!("{}. Retry. Press any key to continue.", e);  wait_for_key_press(); },
                }
            }
            State::ConfigTimeInterval => {
                print_time_interval_menu();
                let time_interval: Result<u64, _> = get_data_from_user().expect("Error while getting time interval from user").parse::<u64>();
                match time_interval {
                    Ok(t) => {
                        packet_snooper.set_time_interval(Duration::from_secs(t as u64));
                    },
                    Err(e) => { println!("{}. Retry. Press any key to continue.", e); wait_for_key_press(); },
                }
            }
            State::ConfigFile => {
                print_config_file_menu();
                let file_name: Result<String, _> = get_data_from_user();
                match file_name {
                    Ok(f) => {
                        packet_snooper.set_file_name(&f);
                        //TODO create file here or in the above function "packet_snooper::set_file_name(&f)"
                    },
                    Err(e) => { println!("{}", e); },
                }
            }
            State::Ready => {
                print_ready_menu();
                let command: Result<String, _> = get_data_from_user();

                match command {
                    Ok(cmd) => {
                        match cmd.to_lowercase().as_str() {
                            "start" => { packet_snooper.start(); },
                            "exit" => { return; }
                            _ => { println!("Invalid command. Retry. Press any key to continue"); wait_for_key_press(); }
                        };
                    },
                    Err(_) => { println!("Something went wrong") }
                };
            },
            State::Working => {
                print_working_menu();
                let command: Result<String, _> = get_data_from_user();

                match command {
                    Ok(cmd) => {
                        match cmd.to_lowercase().as_str() {
                            "abort" => { packet_snooper.abort(); },
                            "end" => { packet_snooper.end(); },
                            "stop" => { packet_snooper.stop(); },
                            "exit" => { return; }
                            _ => { println!("Invalid command. Retry. Press any key to continue"); wait_for_key_press(); }
                        };
                    },
                    Err(_) => { println!("Something went wrong") }
                };
            },
            State::Stopped => {
                print_stopped_menu();
                let command: Result<String, _> = get_data_from_user();

                match command {
                    Ok(cmd) => {
                        match cmd.to_lowercase().as_str() {
                            "abort" => { packet_snooper.abort(); },
                            "end" => { packet_snooper.end(); },
                            "resume" => { packet_snooper.resume(); },
                            "exit" => { return; }
                            _ => { println!("Invalid command. Retry. Press any key to continue"); wait_for_key_press(); }
                        };
                    },
                    Err(_) => { println!("Something went wrong") }
                };
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

fn wait_for_key_press() {
    let mut buffer = String::new();
    io::stdin().lock().read_line(&mut buffer).expect("Something went wrong with user input.");
}

fn retrieve_device(interface_name: &str) -> Result<Device, &'static str> {
    for device in Device::list().unwrap() {
        if interface_name == device.name {
            return Ok(device);
        }
    }
    Err("unable to find device with the specified interface name ")
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

fn print_config_file_menu() {
    print_main_menu();
    println!("File Configuration");
    println!("------------------------");
    println!("Insert the file name you want as report generation target (\"output.txt\" by default) :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn print_ready_menu() {
    print_main_menu();
    println!("Packet Snooper is ready");
    println!("- start");
    println!("- exit");
    println!("------------------------");
    println!("Type command :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn print_working_menu() {
    print_main_menu();
    println!("Packet Snooper is working");
    println!("- abort (back to configuration)");
    println!("- end (back to ready state)");
    println!("- stop");
    println!("- exit");
    println!("------------------------");
    println!("Type command :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn print_stopped_menu() {
    print_main_menu();
    println!("Packet Snooper is stopped");
    println!("- abort (back to configuration)");
    println!("- end (back to ready state)");
    println!("- resume");
    println!("- exit");
    println!("------------------------");
    println!("Type command :");
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
