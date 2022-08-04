//! # packet_snooper
//!
//! `packet_snooper` is a multiplatform library to analyze network traffic data. It's available on Windows and UNIX-like Operating Systems such as Linux and macOS.
//!
//! # Let's get started! Simplified use of packet_snooper library
//!
//! ```
//! let interface_name: &str = "eth0";
//! let time_interval: u64 = 60;
//! let file_name: &str = "hello.txt";
//!
//! let mut packet_snooper = PacketSnooper::new(
//!             interface_name,
//!             time_interval,
//!             file_name).expect("Something went wrong.");  // It's now in state State::Ready
//!
//! // possible operations
//! packet_snooper.start();
//! packet_snooper.stop();
//! packet_snooper.resume();
//! packet_snooper.end();
//! packet_snooper.abort();
//! ```
//!
//! # Suggested Application Structure to use packet_snooper framework
//! This kind of structure is in sync with internal state machine architecture of the packet_snooper framework
//!
//! ```
//! let mut packet_snooper = PacketSnooper::new();
//!
//! loop() {
//!     sleep(Duration::from_millis(50));
//!
//!     match packet_snooper.state {
//!         State::ConfigDevice => {
//!             ...
//!             match packet_snooper.set_device(interface_name.as_str()) {
//!                 Ok(_) => { continue; },
//!                 Err(e) => { println ! ("{}", e);},
//!            }
//!        }
//!        State::ConfigTimeInterval => {
//!            ...
//!            match packet_snooper.set_time_interval(Duration::from_secs(t as u64)) {
//!                Ok(_) => (),
//!                Err(e) => { println ! ("{}", e); },
//!            }
//!        },
//!        State::ConfigFile => {
//!            ...
//!            match packet_snooper.set_file_name(file_name) {
//!                Ok(_) => (),
//!                Err(e) => { println!("{}", e); },
//!            }
//!        },
//!        State::Ready => {
//!            ...
//!            match cmd {
//!                "start" => { packet_snooper.start(); },
//!                "exit" => { return; }
//!                _ => { println ! ("Invalid command"); }
//!            };
//!        },
//!        State::Working => {
//!            ...
//!            match cmd {
//!                "abort" => { packet_snooper.abort(); },
//!                "end" => { packet_snooper.end(); },
//!                "stop" => { packet_snooper.stop(); },
//!                "exit" => { return; }
//!                _ => { println ! ("Invalid command"); },
//!            }
//!        },
//!        State::Stopped => {
//!            ...
//!            match cmd {
//!                "abort" => { packet_snooper.abort(); },
//!                "end" => { packet_snooper.end(); },
//!                "resume" => { packet_snooper.resume(); },
//!                "exit" => { return; }1
//!                _ => { println ! ("Invalid command."); }
//!            }
//!        };
//!    }
//! }
//! ```

mod network_components;
mod utility;

use std::fmt::{Display, Formatter};
use crate::network_components::ethernet_packet::EtherPacket;
use pcap::{Capture, Device, Packet};
use std::{io, thread};
use std::io::{Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, PartialEq)]
/// Internal PacketSnooper States to manage operations.
pub enum State {
    /// Device Selection Stage: Select an interface to be analyzed.
    ConfigDevice,
    /// Time Interval Configuration Stage: Insert time until report generation.
    ConfigTimeInterval,
    /// Filename Configuration Stage: Insert the name of the target file (for report generation).
    ConfigFile,
    /// Ready for network traffic analysis.
    Ready,
    /// Analyzing network traffic.
    Working,
    /// Network traffic analysis is stopped.
    Stopped,
}

/// Struct to manage network analysis.
///
/// # Examples
///
/// ```
/// let mut packet_snooper = PacketSnooper::new();
///
/// match packet_snooper.set_device("wlp3s0") {
///     Ok(_) => (),
///     Err(_) => (),
/// }
/// match packet_snooper.set_time_interval(Duration::from_secs(60)) {
///     Ok(_) => (),
///     Err(_) => (),
/// }
/// match packet_snooper.set_file_name("hello.txt") {
///     Ok(_) => (),
///     Err(_) => (),
/// }
///
/// ```
pub struct PacketSnooper {
    pub state: State,
    pub current_interface: Option<Device>,
    pub time_interval: Duration,
    pub file_name: String,
    stop_thread: Arc<Mutex<bool>>,
    stop_thread_cv: Arc<Condvar>,
    end_thread: Arc<Mutex<bool>>,
    thread: Option<JoinHandle<()>>,
}

impl PacketSnooper {
    pub fn new() -> PacketSnooper {
        PacketSnooper {
            state: State::ConfigDevice,
            current_interface: None,
            time_interval: Duration::from_secs(60),
            file_name: "output.txt".to_owned(),
            stop_thread: Arc::new(Mutex::new(false)),
            stop_thread_cv: Arc::new(Condvar::new()),
            end_thread: Arc::new(Mutex::new(false)),
            thread: Option::from(thread::spawn(move || {})),
        }
    }

    /// Set *`network interface`* (device) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// let interface_name: &str = "eth0";
    /// packet_snooper.set_device(interface_name).unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Unable to find device with the specified interface name`
    /// - `Invalid call on set_device when in an illegal state`
    ///
    /// Handling error cases :
    /// ```
    /// match packet_snooper.set_device(interface_name.as_str()) {
    ///     Ok(_) => (),
    ///     Err(e) => (),
    /// }
    ///
    /// ```
    pub fn set_device(&mut self, interface_name: &str) -> Result<(), &'static str> {
        if self.state == State::ConfigDevice {
            let device = PacketSnooper::retrieve_device(interface_name);
            match device {
                Ok(dev) => {
                    self.state = State::ConfigTimeInterval;
                    self.current_interface = Option::from(dev);
                    Ok(())
                }
                Err(e) => { Err(e) }
            }
        } else {
            Err("Invalid call on set_device when in an illegal state.")
        }
    }

    /// Set *`time interval`* (for report generation) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// let time_interval: u64 = 75;
    /// packet_snooper.set_time_interval(Duration::from_secs(time_interval)).unwrap();
    /// ```
    /// ```
    /// packet_snooper.set_time_interval(Duration::from_secs(75)).unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on set_time_interval when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// let time_interval: u64 = 75;
    /// match packet_snooper.set_time_interval(Duration::from_secs(time_interval)) {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    ///
    pub fn set_time_interval(&mut self, time_interval: Duration) -> Result<(), &'static str> {
        if self.state == State::ConfigTimeInterval {
            self.time_interval = time_interval;
            self.state = State::ConfigFile;
            Ok(())
        } else {
            Err("Invalid call on set_time_interval when in an illegal state.")
        }
    }

    /// Set *`file name`* (as report generation target) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// let file_name: &str = "hello.txt";
    /// packet_snooper.set_file_name(file_name).unwrap();
    /// ```
    /// ```
    /// packet_snooper.set_file_name("hello.txt").unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid file name given as a parameter` (not supported yet)
    /// - `Invalid call on set_file_name when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// let file_name: &str = "hello.txt";
    ///
    /// match packet_snooper.set_file_name(file_name) {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn set_file_name(&mut self, file_name: &str) -> Result<(), &'static str>{
        if self.state == State::ConfigFile {
            // TODO check filename is correct
            self.file_name = file_name.to_owned();
            self.state = State::Ready;
            Ok(())
        } else {
            Err("Invalid call on set_file_name when in an illegal state.")
        }
    }

    pub fn start(&mut self) {
        *self.stop_thread.lock().unwrap() = false;
        *self.end_thread.lock().unwrap() = false;
        let stop_thread = self.stop_thread.clone();
        let stop_thread_cv = self.stop_thread_cv.clone();
        let end_thread = self.end_thread.clone();

        self.thread = Option::from(thread::spawn(move || {
            let mut i = 0;
            loop {
                thread::sleep(Duration::from_secs(1));
                if *end_thread.lock().unwrap() == true {
                    return;
                }
                let mut stop_flag = *stop_thread.lock().unwrap();
                while stop_flag == true {
                    stop_flag = *stop_thread_cv.wait(stop_thread.lock().unwrap()).unwrap();
                }
                println!("working...{}", i);
                i += 1;
            }
        }));
        self.state = State::Working;
    }

    pub fn stop(&mut self) {
        *self.stop_thread.lock().unwrap() = true;
        self.stop_thread_cv.notify_one();
        self.state = State::Stopped;
    }

    pub fn resume(&mut self) {
        *self.stop_thread.lock().unwrap() = false;
        self.stop_thread_cv.notify_one();
        self.state = State::Working;
    }

    pub fn end(&mut self) {
        *self.end_thread.lock().unwrap() = true;
        self.thread.take().map(JoinHandle::join);
        self.state = State::Ready;
    }

    pub fn abort(&mut self) {
        *self.end_thread.lock().unwrap() = true;
        self.thread.take().map(JoinHandle::join);
        self.state = State::ConfigDevice;
    }

    fn retrieve_device(interface_name: &str) -> Result<Device, &'static str> {
        for device in Device::list().unwrap() {
            if interface_name == device.name {
                return Ok(device);
            }
        }
        Err("unable to find device with the specified interface name ")
    }

    pub fn test_simple_read_packets() {
        let main_device = Device::lookup().unwrap();
        let mut cap = Capture::from_device(main_device).unwrap()
                .promisc(true)
                .open().unwrap();

        while let Ok(packet) = cap.next() {
            PacketSnooper::decode_packet(packet);
        }
    }

    pub fn decode_packet(packet: Packet) {
        let data = packet.data;

        let ethernet_packet = EtherPacket::new(&data[..]);

        println!("---------------");
        println!("{}", ethernet_packet);
        io::stdout().flush().unwrap();
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
                    }
                    false => {
                        write!(f, "None")
                    }
                }
            }
            false => { write!(f, "[interface: None]") }
        }.unwrap();
        write!(f, "\nInternal State: {:?}", self.state).unwrap();
        write!(f, "\nTime interval before report generation : {:?}", self.time_interval).unwrap();
        write!(f, "\nFile name Target for report generation: {:?}", self.file_name)
    }
}
