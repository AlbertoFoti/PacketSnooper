use std::io;
use std::io::{BufRead, Write};
use pcap::{Device, Error};
use packet_snooper::{PacketSnooper, State};

fn main() {
    let mut packet_snooper = PacketSnooper::new();
    println!("{}", packet_snooper);

    loop {
        clear_screen();

        match packet_snooper.state {
            State::ConfigDevice => {
                print_interface_menu();
                let interface_name = get_data_from_user().expect("Error while getting interface name from user");

                match packet_snooper.set_device(interface_name.as_str()) {
                    Ok(_) => { continue; },
                    Err(e) => { println!("{}. Retry. Press any key to continue.", e);  wait_for_key_press(); },
                }
            }
            State::ConfigTimeInterval => {
                print_time_interval_menu();
                let time_interval: Result<u64, _> = get_data_from_user().expect("Error while getting time interval from user").parse::<u64>();

                match time_interval {
                    Ok(t) => {
                        match packet_snooper.set_time_interval(t as u64) {
                            Ok(_) => { continue; },
                            Err(e) => { println!("{}. Retry. Press any key to continue.", e); wait_for_key_press(); },
                        }
                    },
                    Err(e) => { println!("{}. Retry. Press any key to continue.", e); wait_for_key_press(); },
                }
            }
            State::ConfigFile => {
                print_config_file_menu();
                let file_name: Result<String, _> = get_data_from_user();
                match file_name {
                    Ok(f) => {
                        match packet_snooper.set_file_path(&f) {
                            Ok(_) => { continue; },
                            Err(e) => { println!("{}. Retry. Press any key to continue.", e); wait_for_key_press(); },
                        }
                    },
                    Err(e) => { println!("{}", e); },
                }
            }
            State::ReportFormat => {
                print_report_format_menu();
                let format_report = get_data_from_user();
                match format_report {
                    Ok(f) => {
                        match packet_snooper.set_report_format(&f) {
                            Ok(_) => { continue; },
                            Err(e) => { println!("{}. Retry. Press any key to continue.", e); wait_for_key_press(); },
                        }
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
                            "start" => { packet_snooper.start().unwrap(); },
                            "abort" => { packet_snooper.abort().unwrap(); },
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
                            "abort" => { packet_snooper.abort().unwrap(); },
                            "end" => { packet_snooper.end().unwrap(); },
                            "stop" => { packet_snooper.stop().unwrap(); },
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
                            "abort" => { packet_snooper.abort().unwrap(); },
                            "end" => { packet_snooper.end().unwrap(); },
                            "resume" => { packet_snooper.resume().unwrap(); },
                            "exit" => { return; }
                            _ => { println!("Invalid command. Retry. Press any key to continue"); wait_for_key_press(); }
                        };
                    },
                    Err(_) => { println!("Something went wrong") }
                };
            }
        }
    }
}

fn get_data_from_user() -> Result<String, Error> {
    let mut buffer = String::new();
    io::stdin().lock().read_line(&mut buffer)?;
    if cfg!(unix) { buffer.pop(); }
    else if cfg!(windows) { buffer.pop(); buffer.pop(); }
    Ok(buffer)
}

fn wait_for_key_press() {
    let mut buffer = String::new();
    io::stdin().lock().read_line(&mut buffer).expect("Something went wrong with user input.");
}

fn print_interfaces() -> () {
    println!("List of available interfaces: ");
    for device in Device::list().unwrap() {
        print!("[{:?} ] : ", device.name);
        for address in device.addresses {
            println!(
                "[{:?} / {:?}]",
                address.addr, address.netmask
            );
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

fn print_report_format_menu() {
    print_main_menu();
    println!("Report format selection");
    println!("------------------------");
    println!("Choose the format of the packets shown in the report (raw/verbose/quiet) :");
    print!(">>> ");
    io::stdout().flush().unwrap();
}

fn print_ready_menu() {
    print_main_menu();
    println!("Packet Snooper is ready");
    println!("- start");
    println!("- abort");
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
        std::process::Command::new("cmd").args(&["/c", "cls"]).status().unwrap();
    }
}
