//! # packet_snooper
//!
//! `packet_snooper` is a multiplatform library to analyze network traffic data. It's available on Windows and UNIX-like Operating Systems such as Linux and macOS.
//!
//! It was developed as part of a University project (Politecnico of Turin, Italy. "System and Device Programming". Year 2022).
//!
//! ( credits: Alberto Foti, Samuele Giannetto, Simone Annecchini )
//!
//! # Let's get started! Simplified use of packet_snooper library
//!
//! ```
//! let interface_name: &str = "eth0";
//! let time_interval: u64 = 60;
//! let file_name: &str = "hello.txt";
//!
//! let mut packet_snooper = PacketSnooper::new().with_details(
//!             interface_name,
//!             time_interval,
//!             file_name).expect("Something went wrong.");  // It's now in state State::Ready
//!
//! // possible operations
//! packet_snooper.start().unwrap();
//! packet_snooper.stop().unwrap();
//! packet_snooper.resume().unwrap();
//! packet_snooper.end().unwrap();
//! packet_snooper.abort().unwrap();
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
//!                 Err(e) => { println!("{}", e); },
//!            }
//!        }
//!        State::ConfigTimeInterval => {
//!            ...
//!            match packet_snooper.set_time_interval(t as u64) {
//!                Ok(_) => { continue; },
//!                Err(e) => { println ! ("{}", e); },
//!            }
//!        },
//!        State::ConfigFile => {
//!            ...
//!            match packet_snooper.set_file_name(file_name) {
//!                Ok(_) => { continue; },
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
//!                "exit" => { return; },
//!                _ => { println ! ("Invalid command."); }
//!            }
//!        };
//!    }
//! }
//! ```

// Easy tasks
// TODO : complete documentation
// TODO : in-depth testing

// Major tasks
// TODO : timer for report generation implemented
// TODO : file report generation

// Advanced (optional)
// TODO : filters
// TODO : --verbose, --quiet report type

// Maintenance
// TODO : check documentation correctness
// TODO : refactor of network components struct and modules

pub mod network_components;
pub mod utility;

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
/// match packet_snooper.set_time_interval(60) {
///     Ok(_) => (),
///     Err(_) => (),
/// }
/// match packet_snooper.set_file_name("hello.txt") {
///     Ok(_) => (),
///     Err(_) => (),
/// }
/// ```
/// ```
/// let interface_name: &str = "eth0";
/// let time_interval: u64 = 75;
/// let file_name: &str = "dump.txt";
/// let mut packet_snooper = PacketSnooper::new().with_details(
///             interface_name,
///             time_interval,
///             file_name).expect("Something went wrong.");
/// ```
pub struct PacketSnooper {
    /// Internal state (for configuration and management of operations purposes)
    pub state: State,
    /// Interface name (as target of network traffic analysis)
    pub current_interface: String,
    /// Time interval (until report generation)
    pub time_interval: Duration,
    /// File name (as target of report generation)
    pub file_name: String,

    stop_thread: Arc<Mutex<bool>>,
    stop_thread_cv: Arc<Condvar>,
    end_thread: Arc<Mutex<bool>>,
    thread: Option<JoinHandle<()>>,
}

impl PacketSnooper {
    /// PacketSnooper struct Constructor
    /// # Examples
    /// ```
    /// let mut packet_snooper = PacketSnooper::new();
    /// ```
    pub fn new() -> PacketSnooper {
        PacketSnooper {
            state: State::ConfigDevice,
            current_interface: String::from(Device::lookup().unwrap().name),
            time_interval: Duration::from_secs(60),
            file_name: "output.txt".to_owned(),
            stop_thread: Arc::new(Mutex::new(false)),
            stop_thread_cv: Arc::new(Condvar::new()),
            end_thread: Arc::new(Mutex::new(false)),
            thread: Option::from(thread::spawn(move || {})),
        }
    }

    /// PacketSnooper struct Constructor with details (automatic configuration when building the PacketSnooper object)
    /// # Examples
    /// ```
    /// let interface_name: &str = "eth0";
    /// let time_interval: u64 = 75;
    /// let file_name: &str = "dump.txt";
    /// let mut packet_snooper = PacketSnooper::new().with_details(
    ///             interface_name,
    ///             time_interval,
    ///             file_name).expect("Something went wrong.");
    /// ```
    pub fn with_details(mut self, interface_name: &str, time_interval: u64, file_name: &str) -> Result<PacketSnooper, &'static str> {
        self.set_device(interface_name)?;
        self.set_time_interval(time_interval)?;
        self.set_file_name(file_name)?;
        Ok(self)
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
    ///     Err(e) => ( println!("{}", e); ),
    /// }
    ///
    /// ```
    pub fn set_device(&mut self, interface_name: &str) -> Result<(), &'static str> {
        if self.state == State::ConfigDevice {
            let device = PacketSnooper::retrieve_device(interface_name);
            match device {
                Ok(dev) => {
                    self.state = State::ConfigTimeInterval;
                    self.current_interface = dev.name.clone();
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
    /// packet_snooper.set_time_interval(time_interval).unwrap();
    /// ```
    /// ```
    /// packet_snooper.set_time_interval(75).unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on set_time_interval when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// let time_interval: u64 = 75;
    /// match packet_snooper.set_time_interval(time_interval) {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    ///
    pub fn set_time_interval(&mut self, time_interval: u64) -> Result<(), &'static str> {
        if self.state == State::ConfigTimeInterval {
            self.time_interval = Duration::from_secs(time_interval);
            self.state = State::ConfigFile;
            Ok(())
        } else {
            Err("Invalid call on set_time_interval when in an illegal state.")
        }
    }

    /// Set *`file name`* (as report generation target) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// Transitions from ConfigFile state to Ready state.
    /// PacketSnooper is now configured and ready to analyze network traffic
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

    /// *`start`* network traffic analysis inside PacketSnooper framework.
    ///
    /// Transitions from Ready state to Working state, spawning a worker thread able to analyze network traffic.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// packet_snooper.start().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on start when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.start() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn start(&mut self) -> Result<(), &'static str> {
        if self.state != State::Ready { return Err("Invalid call on start when in an illegal state"); }

        let interface_name = self.current_interface.clone();

        *self.stop_thread.lock().unwrap() = false;
        *self.end_thread.lock().unwrap() = false;
        let stop_thread = self.stop_thread.clone();
        let stop_thread_cv = self.stop_thread_cv.clone();
        let end_thread = self.end_thread.clone();

        self.thread = Option::from(thread::spawn(self.network_analysis(interface_name, stop_thread, stop_thread_cv, end_thread)));
        self.state = State::Working;
        Ok(())
    }

    /// *`stop`* network traffic analysis inside PacketSnooper framework.
    ///
    /// Transitions from Working state to Stopped state, temporarily halting all operations.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// packet_snooper.stop().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on stop when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.stop() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn stop(&mut self) -> Result<(), &'static str> {
        if self.state != State::Working { return Err("Invalid call on stop when in an illegal state"); }

        *self.stop_thread.lock().unwrap() = true;
        self.stop_thread_cv.notify_one();
        self.state = State::Stopped;
        Ok(())
    }

    /// *`resume`* network traffic analysis inside PacketSnooper framework.
    ///
    /// Transitions from Stopped state to Working state, resuming all operations.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// packet_snooper.resume().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on resume when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.resume() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn resume(&mut self) -> Result<(), &'static str> {
        if self.state != State::Stopped { return Err("Invalid call on resume when in an illegal state"); }

        *self.stop_thread.lock().unwrap() = false;
        self.stop_thread_cv.notify_one();
        self.state = State::Working;
        Ok(())
    }

    /// *`end`* network traffic analysis inside PacketSnooper framework.
    ///
    /// Transitions from Working/Stopped state to Ready state, halting and scrapping progresses, but keeping configuration info.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// packet_snooper.end().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on end when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.end() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn end(&mut self) -> Result<(), &'static str> {
        if self.state != State::Working && self.state != State::Stopped { return Err("Invalid call on end when in an illegal state"); }

        *self.end_thread.lock().unwrap() = true;
        self.thread.take().map(JoinHandle::join);
        self.state = State::Ready;
        Ok(())
    }

    /// *`abort`* network traffic analysis and configuration inside PacketSnooper framework.
    ///
    /// Transitions from ??? state to ConfigDevice state, halting and scrapping progresses, including configuration info.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// packet_snooper.abort().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid call on abort when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.abort() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn abort(&mut self) -> Result<(), &'static str> {
        // TODO return Err(e) when in an illegal state. Are there illegal states for abort???!
        *self.end_thread.lock().unwrap() = true;
        // TODO make sure nothing breaks here as take() is done in all states -> Test
        self.thread.take().map(JoinHandle::join);
        self.state = State::ConfigDevice;
        Ok(())
    }

    fn retrieve_device(interface_name: &str) -> Result<Device, &'static str> {
        for device in Device::list().unwrap() {
            if interface_name == device.name {
                return Ok(device);
            }
        }
        Err("unable to find device with the specified interface name ")
    }

    fn network_analysis(&self, interface_name: String, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>, end_thread: Arc<Mutex<bool>>) -> impl FnOnce() -> () {
        let timeout = 50;
        let mut cap = Capture::from_device(interface_name.as_str()).unwrap()
                .promisc(true)
                .timeout(timeout)
                .open().unwrap();

        move || {
            loop {
                if *end_thread.lock().unwrap() == true {
                    break;
                }
                let mut stop_flag = *stop_thread.lock().unwrap();
                while stop_flag == true {
                    stop_flag = *stop_thread_cv.wait(stop_thread.lock().unwrap()).unwrap();
                    cap = Capture::from_device(Device::from(interface_name.as_str())).unwrap()
                            .promisc(true)
                            .timeout(timeout)
                            .open().unwrap();
                }
                if let Ok(packet) = cap.next() {
                    PacketSnooper::decode_packet(packet);
                }
            }
        }
    }

    fn decode_packet(packet: Packet) {
        let data = packet.data;

        let ethernet_packet = EtherPacket::new(&data[..]);

        println!("---------------");
        println!("{}", ethernet_packet);
        io::stdout().flush().unwrap();
    }
}

impl Display for PacketSnooper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Packet-Snooper: [interface: {} / ", self.current_interface).unwrap();
        let device = Device::from(self.current_interface.as_str());
        match device.addresses.get(0) {
            Some(addr) => { write!(f, "{:?}", addr.addr) },
            None => { write!(f, "None") }
        }.unwrap();
        write!(f, "\nInternal State: {:?}", self.state).unwrap();
        write!(f, "\nTime interval before report generation : {:?}", self.time_interval).unwrap();
        write!(f, "\nFile name Target for report generation: {:?}", self.file_name)
    }
}
