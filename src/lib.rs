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
//! let file_path: &str = "hello.txt";
//!
//! let mut packet_snooper = PacketSnooper::new().with_details(
//!             interface_name,
//!             time_interval,
//!             file_path).expect("Something went wrong.");  // It's now in state State::Ready
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
//!            match packet_snooper.set_file_path(file_path) {
//!                Ok(_) => { continue; },
//!                Err(e) => { println!("{}", e); },
//!            }
//!        },
//!        State::Ready => {
//!            ...
//!            match cmd {
//!                "start" => { packet_snooper.start().unwrap(); },
//!                "abort" => { packet_snooper.abort().unwrap(); },
//!                "exit" => { return; }
//!                _ => { println ! ("Invalid command"); }
//!            };
//!        },
//!        State::Working => {
//!            ...
//!            match cmd {
//!                "abort" => { packet_snooper.abort().unwrap(); },
//!                "end" => { packet_snooper.end().unwrap(); },
//!                "stop" => { packet_snooper.stop().unwrap(); },
//!                "exit" => { return; }
//!                _ => { println ! ("Invalid command"); },
//!            }
//!        },
//!        State::Stopped => {
//!            ...
//!            match cmd {
//!                "abort" => { packet_snooper.abort().unwrap(); },
//!                "end" => { packet_snooper.end().unwrap(); },
//!                "resume" => { packet_snooper.resume().unwrap(); },
//!                "exit" => { return; },
//!                _ => { println ! ("Invalid command."); }
//!            }
//!        };
//!    }
//! }
//! ```

// Easy tasks
// TODO : MacOS as a github action workflow for CI/CD

// Major tasks
// TODO : expanding state machine to allow multiple kinds of report type

// Advanced (optional)
// TODO : filters   (???)
// TODO : expanding the collection of protocols supported

// Future stuff to do
// TODO : in-depth concurrency testing (Alberto, Samuele)
// TODO : tests for IPv6 packet  (Alberto)
// TODO : handling all error cases in a good way (...)
// TODO : complete documentation and check for correctness (Alberto, Samuele)

extern crate core;

pub mod network_components;
pub mod report_generator;
pub mod utility;

#[cfg(test)]
mod tests;

use std::fmt::{Display, Formatter};
use pcap::{Capture, Device, Packet};
use std::{thread};
use std::error::Error;
use std::path::{PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread::{JoinHandle};
use std::time::Duration;
use crate::network_components::layer_2::ethernet_packet::EthernetPacket;
use crate::report_generator::{ReportFormat, ReportGenerator};

const CAPTURE_BUFFER_TIMEOUT_MS: i32 = 25;

#[derive(Debug, PartialEq)]
/// Packet Snooper custom Error type PSError.
pub struct PSError {
    /// Message describing the error.
    pub message: String,
}

impl PSError {
    pub fn new(msg: &str) -> Self {
        PSError { message: msg.to_string() }
    }
}

impl Display for PSError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PSError: {}", self.message)
    }
}

impl Error for PSError {}

type Result<T> = std::result::Result<T, PSError>;

#[derive(Debug, PartialEq)]
/// Internal PacketSnooper States to manage operations.
pub enum State {
    /// Device Selection Stage: Select an interface to be analyzed.
    ConfigDevice,
    /// Time Interval Configuration Stage: Insert time until report generation.
    ConfigTimeInterval,
    /// Filename Configuration Stage: Insert the name of the target file (for report generation).
    ConfigFile,
    /// Format of the report Stage: Decide how packets will be shown (raw,verbose,quit)
    ReportFormat,
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
/// match packet_snooper.set_file_path("hello.txt") {
///     Ok(_) => (),
///     Err(_) => (),
/// }
/// ```
/// ```
/// let interface_name: &str = "eth0";
/// let time_interval: u64 = 75;
/// let file_path: &str = "dump.txt";
/// let mut packet_snooper = PacketSnooper::new().with_details(
///             interface_name,
///             time_interval,
///             file_path).expect("Something went wrong.");
/// ```
pub struct PacketSnooper {
    /// Internal state (for configuration and management of operations purposes)
    pub state: State,
    /// Interface name (as target of network traffic analysis)
    pub current_interface: String,
    /// Time interval (until report generation)
    pub time_interval: Duration,
    /// File Path (as target of report generation)
    pub file_path: PathBuf,
    /// Report Format
    pub report_format: ReportFormat,

    stop_thread: Arc<Mutex<bool>>,
    stop_thread_cv: Arc<Condvar>,
    end_thread: Arc<Mutex<bool>>,
    network_capture_thread: Option<JoinHandle<()>>,
    consumer_thread: Option<JoinHandle<()>>,
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
            file_path: PathBuf::from("output.txt"),
            report_format: ReportFormat::Quiet,
            stop_thread: Arc::new(Mutex::new(false)),
            stop_thread_cv: Arc::new(Condvar::new()),
            end_thread: Arc::new(Mutex::new(false)),
            network_capture_thread: None,
            consumer_thread: None,
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
    pub fn with_details(mut self, interface_name: &str, time_interval: u64, file_path: &str) -> Result<PacketSnooper> {
        self.set_device(interface_name)?;
        self.set_time_interval(time_interval)?;
        self.set_file_path(file_path)?;
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
    pub fn set_device(&mut self, interface_name: &str) -> Result<()> {
        if self.state == State::ConfigDevice {
            let device = PacketSnooper::retrieve_device(interface_name)?;
            self.state = State::ConfigTimeInterval;
            self.current_interface = device.name.clone();
            Ok(())
        } else {
            Err(PSError::new("Invalid call on set_device when in an illegal state."))
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
    pub fn set_time_interval(&mut self, time_interval: u64) -> Result<()> {
        if self.state == State::ConfigTimeInterval {
            self.time_interval = Duration::from_secs(time_interval);
            self.state = State::ConfigFile;
            Ok(())
        } else {
            Err(PSError::new("Invalid call on set_time_interval when in an illegal state."))
        }
    }

    /// Set *`file path`* (as report generation target) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// let file_path: &str = "hello.txt";
    /// packet_snooper.set_file_path(file_path).unwrap();
    /// ```
    /// ```
    /// packet_snooper.set_file_path("hello.txt").unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid file name given as a parameter` (not supported yet)
    /// - `Invalid call on set_file_path when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// let file_path: &str = "hello.txt";
    ///
    /// match packet_snooper.set_file_path(file_path) {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn set_file_path(&mut self, file_path: &str) -> Result<()>{
        if self.state == State::ConfigFile {
            // TODO check file path is correct
            self.file_path = PathBuf::from(file_path);
            self.state = State::ReportFormat;
            Ok(())
        } else {
            Err(PSError::new("Invalid call on set_file_path when in an illegal state."))
        }
    }

    /// Set *`report_format`* (as format of the packets in the report) inside PacketSnooper struct.
    /// It's part of the configuration phase.
    ///
    /// Transitions from ConfigFile state to Ready state.
    /// PacketSnooper is now configured and ready to analyze network traffic
    ///
    /// # Examples
    ///
    /// Simplified call (without error handling)
    /// ```
    /// let report_format: &str = "verbose";
    /// packet_snooper.set_report_format(report_format).unwrap();
    /// ```
    /// ```
    /// packet_snooper.set_report_format("verbose").unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Invalid format name given as a parameter`
    /// - `Invalid call on set_report_format when in an illegal state`
    ///
    /// Handling error cases:
    /// ```
    /// let report_format: &str = "verbose";
    ///
    /// match packet_snooper.set_report_format(report_format) {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn set_report_format(&mut self, report_format: &str) -> Result<()>{
        if self.state == State::ReportFormat {
            match report_format {
                "raw" => { self.report_format = ReportFormat::Raw },
                "quiet" => { self.report_format = ReportFormat::Quiet },
                "verbose" => { self.report_format = ReportFormat::Verbose }
                _ => {
                    return Err(PSError::new("Invalid format name given as a parameter"))
                }
            }
            self.state = State::Ready;
            Ok(())
        } else {
            Err(PSError::new("Invalid call on set_report_format when in an illegal state."))
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
    pub fn start(&mut self) -> Result<()> {
        if self.state != State::Ready { return Err(PSError::new("Invalid call on start when in an illegal state.")); }

        let interface_name = self.current_interface.clone();

        *self.stop_thread.lock().unwrap() = false;
        *self.end_thread.lock().unwrap() = false;

        let ( tx, rx ) = channel();

        self.network_capture_thread = Option::from(thread::spawn(PacketSnooper::network_analysis(
            interface_name,
            self.stop_thread.clone(),
            self.stop_thread_cv.clone(),
            self.end_thread.clone(),
            tx)));
        self.consumer_thread = Option::from(thread::spawn(PacketSnooper::consume_packets(
            self.file_path.clone(),
            self.time_interval.as_secs(),
            self.report_format.clone(),
            self.stop_thread.clone(),
            self.stop_thread_cv.clone(),
            Box::new(rx))));

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
    pub fn stop(&mut self) -> Result<()> {
        if self.state != State::Working { return Err(PSError::new("Invalid call on stop when in an illegal state.")); }

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
    pub fn resume(&mut self) -> Result<()> {
        if self.state != State::Stopped { return Err(PSError::new("Invalid call on resume when in an illegal state.")); }

        *self.stop_thread.lock().unwrap() = false;
        self.stop_thread_cv.notify_all();

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
    pub fn end(&mut self) -> Result<()> {
        if self.state != State::Working && self.state != State::Stopped { return Err(PSError::new("Invalid call on end when in an illegal state.")); }

        *self.end_thread.lock().unwrap() = true;
        *self.stop_thread.lock().unwrap() = false;
        self.stop_thread_cv.notify_all();

        self.network_capture_thread.take().map(JoinHandle::join);
        self.consumer_thread.take().map(JoinHandle::join);

        self.state = State::Ready;
        Ok(())
    }

    /// *`abort`* network traffic analysis and configuration inside PacketSnooper framework.
    ///
    /// Transitions from every state to ConfigDevice state, halting and scrapping progresses, including configuration info.
    ///
    /// # Examples
    ///
    /// ```
    /// packet_snooper.abort().unwrap();
    /// ```
    ///
    /// # Error
    ///
    /// - `Something went wrong inside the analyzer thread. Err returned as a result of join.`
    /// - `Something went wrong inside the consumer thread. Err returned as a result of join.`
    ///
    /// Handling error cases:
    /// ```
    /// match packet_snooper.abort() {
    ///     Ok(_) => (),
    ///     Err(e) => { println!("{}", e); },
    /// }
    /// ```
    pub fn abort(&mut self) -> Result<()> {
        *self.end_thread.lock().unwrap() = true;
        *self.stop_thread.lock().unwrap() = false;
        self.stop_thread_cv.notify_all();

        match self.network_capture_thread.take() {
            Some(res) => {
                match res.join() {
                    Ok(_) => (),
                    Err(_) => { return Err(PSError::new("Something went wrong inside the analyzer thread. Err returned as a result of join."))}
                }
            },
            None => (),
        };
        match self.consumer_thread.take() {
            Some(res) => {
                match res.join() {
                    Ok(_) => (),
                    Err(_) => { return Err(PSError::new("Something went wrong inside the consumer thread. Err returned as a result of join."))}
                }
            },
            None => (),
        };

        self.state = State::ConfigDevice;
        Ok(())
    }

    fn retrieve_device(interface_name: &str) -> Result<Device> {
        for device in Device::list().unwrap() {
            if interface_name == device.name {
                return Ok(device);
            }
        }
        Err(PSError::new("unable to find device with the specified interface name "))
    }

    fn network_analysis(interface_name: String, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>, end_thread: Arc<Mutex<bool>>, tx: Sender<String>) -> impl FnOnce() -> () {
        let mut cap = Capture::from_device(interface_name.as_str()).unwrap()
                .promisc(true)
                .timeout(CAPTURE_BUFFER_TIMEOUT_MS)
                .open().unwrap()
                .setnonblock().unwrap();

        move || {
            loop {
                if *end_thread.lock().unwrap() == true {
                    drop(cap);
                    break;
                }
                let mut stop_flag = *stop_thread.lock().unwrap();
                while stop_flag == true {
                    stop_flag = *stop_thread_cv.wait(stop_thread.lock().unwrap()).unwrap();
                    cap = Capture::from_device(interface_name.as_str()).unwrap()
                            .promisc(true)
                            .timeout(CAPTURE_BUFFER_TIMEOUT_MS)
                            .open().unwrap()
                            .setnonblock().unwrap();
                }
                if let Ok(packet) = cap.next() {
                    if *end_thread.lock().unwrap() == false && *stop_thread.lock().unwrap() == false {
                            tx.send(PacketSnooper::decode_packet(packet).to_json()).unwrap();
                    }
                }
            }
        }
    }

    fn consume_packets(file_path: PathBuf, time_interval: u64, report_format: ReportFormat, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>, rx: Box<Receiver<String>>) -> impl FnOnce() -> () {
        move || {
            let mut report_generator = ReportGenerator::new(file_path, time_interval, report_format, stop_thread, stop_thread_cv).expect("Something went wrong");

            while let Ok(packet) = rx.recv() {
                report_generator.push(&packet);
            }
        }
    }

    fn decode_packet(packet: Packet) -> EthernetPacket {
        let data = packet.data;
        EthernetPacket::new(data)
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
        write!(f, "\nFile path Target for report generation: {:?}", self.file_path)
    }
}

impl Drop for PacketSnooper {
    fn drop(&mut self) {

    }
}
