//! # Report Generator
//!
//! Module to handle `periodic report generation` about the traffic analyzed.
//!

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::io::{Write};
use std::path::{PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use crate::{ConfigOptions, EthernetPacket};
use std::time::{Duration};
use std::thread;
use std::thread::JoinHandle;
use chrono::{DateTime, Utc};

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq)]
/// Report Generator custom Error type `RGError`.
pub struct RGError {
    /// Message describing the error.
    pub message: String,
}

impl RGError {
    pub fn new(msg: &str) -> Self {
        RGError { message: msg.to_string() }
    }
}

impl Display for RGError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RGError: {}", self.message)
    }
}

impl Error for RGError {}

type Result<T> = std::result::Result<T, RGError>;

impl From<std::io::Error> for RGError {
    fn from(obj: std::io::Error) -> RGError {
        RGError::new(format!("io::Error : {:?}", obj.to_string()).as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
/// `Report Format` enum for report type generation
///
/// # Examples
///
/// - Raw: Layer 2 protocol + Layer 3 protocol + Layer 4 protocol (simple and raw dump/report)
/// ```
/// Ethernet IPV4 UDP
/// ```
/// - Verbose: list of all packets captures. In depth analysis of each single packet
/// ```
/// Ethernet : 74:e5:f9:16:ee:9b -> e0:b9:e5:30:ef:98
/// IPv4     : 151.99.51.205 -> 192.168.1.119
///  > [version: 4, header-length: 20B, diff-serv: 0x00, tot-length: 1278B, identification: 0x59f9, flags: 0x00, frag-offset: 0, ttl: 123, header-checksum: 0x53a6 ]
///  > []
/// UDP      : 443 -> 58776  - [length: 1258, checksum: 0x3ac6]
/// HTTPS   : Protocol details unknown
///  > [5316a3ef6a27bfbabfc244c649d4ccace446e75d84ccd4375195135b63bb3341d7393688672704bce19900ad6a3364b163b535a7a7c2d65d03d7f3a43ebdc6d107c92ba82c638eab45f8e9...]
/// ```
/// - Report
/// ```
/// IP src          | IP dst          | Port src  | Port dst  | L4 Protocol     | Upper Service   | Num. Bytes      | Initial Timestamp                 | Final Timestamp
/// 192.168.1.119   | 142.250.184.46  | 46374     | 443       | UDP             | HTTPS           | 5906            | 2022-08-11 21:33:46.756617241 UTC | 2022-08-11 21:33:49.164702665 UTC
/// 192.168.1.119   | 142.250.184.46  | 40589     | 443       | UDP             | HTTPS           | 3653            | 2022-08-11 21:33:49.964760509 UTC | 2022-08-11 21:33:50.125081873 UTC
/// 192.168.1.119   | 140.82.121.3    | 39322     | 443       | TCP             | HTTPS           | 1849            | 2022-08-11 21:33:35.232940691 UTC | 2022-08-11 21:33:36.096701586 UTC
/// ```
///
pub enum ReportFormat {
    /// Simple analysis of each packet captured.
    Raw,
    /// In depth analysis of each packet captured.
    Verbose,
    /// Brief summary collapsed for IPs, ports, L4 protocol. Initial and final timestamps of packets belonging to the corresponding class are available.
    Report,
}

#[derive(Debug, Clone)]
/// `Report Info` for "report" format generation
pub struct ReportDataInfo {
    /// IP source
    pub ip_src: String,
    /// IP destination
    pub ip_dst: String,
    /// Port source
    pub port_src: u16,
    /// Port destination
    pub port_dst: u16,
    /// Layer 4 protocol (TCP/UDP/...)
    pub l4_protocol: String,
    /// Upper layer service (HTTP/...)
    pub upper_service: String,
    /// Size in bytes
    pub num_bytes: usize,
    /// Timestamp of received packet
    pub timestamp_recv: DateTime<Utc>,
}

#[derive(Debug, Clone)]
/// `Report Entry` for report generation
pub struct ReportEntry {
    /// IP source
    pub ip_src: String,
    /// IP destination
    pub ip_dst: String,
    /// Port source
    pub port_src: u16,
    /// Port destination
    pub port_dst: u16,
    /// Layer 4 protocol (TCP/UDP/...)
    pub l4_protocol: String,
    /// Upper layer service (HTTP/...)
    pub upper_service: String,
    /// Number of bytes received
    pub num_bytes: usize,
    /// Timestamp of the first packet received belonging in this class
    pub timestamp_init: DateTime<Utc>,
    /// Timestamp of the last packet received belonging in this class
    pub timestamp_final: DateTime<Utc>,
}

impl Display for ReportEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0: <15} | {1: <15} | {2: <9} | {3: <9} | {4: <15} | {5: <15} | {6: <15} | {7: <35} | {8: <35}",
            self.ip_src,
            self.ip_dst,
            self.port_src,
            self.port_dst,
            self.l4_protocol,
            self.upper_service,
            self.num_bytes,
            self.timestamp_init,
            self.timestamp_final)
    }
}

/// `DisplayAs` trait
/// Used to display packet in different ways depending on a Format specifier
pub trait DisplayAs {
    fn display_as(&self, report_format: ReportFormat) -> String;
}

/// `Inner Report Generator` used for inner mutability in a thread-safe environment.
pub struct InnerReportGenerator {
    /// Path of the target file for report generation
    file_path: PathBuf,
    /// Time interval of the periodic report generation
    time_interval: Duration,
    /// Type of report
    report_format: ReportFormat,
    /// Filters applied to incoming packets
    packet_filter: String,

    /// Raw data used for Verbose report generation
    data: Vec<u8>,
    /// Formatted data collapsed for a series of key elements (IPs, Ports, L4 protocol)
    data_format: HashMap<String, ReportEntry>,
}

impl InnerReportGenerator {
    /// `new`
    pub fn new(config_options: ConfigOptions) -> Result<Self> {
        Ok(Self {
            file_path: config_options.file_path,
            time_interval: config_options.time_interval,
            report_format: config_options.report_format,
            packet_filter: config_options.packet_filter,
            data: Vec::new(),
            data_format: HashMap::new(),
        })
    }

    /// `push` into raw data or data_format data. Used later for report generation.
    pub fn push(&mut self, packet: &str) {
        match self.report_format {
            ReportFormat::Report => {
                match EthernetPacket::from_json(&packet).unwrap().report_data() {
                    Some(rg_info) => {
                        let key = self.key_gen(rg_info.clone());

                        // add to hash map
                        let value = ReportEntry {
                            ip_src: rg_info.ip_src,
                            ip_dst: rg_info.ip_dst,
                            port_src: rg_info.port_src,
                            port_dst: rg_info.port_dst,
                            l4_protocol: rg_info.l4_protocol,
                            upper_service: rg_info.upper_service,
                            num_bytes: rg_info.num_bytes,
                            timestamp_init: rg_info.timestamp_recv,
                            timestamp_final: rg_info.timestamp_recv };

                        if self.apply_filter(&key) {
                            let entry = self.data_format.entry(key).or_insert(value);
                            entry.num_bytes += rg_info.num_bytes;
                            entry.timestamp_final = rg_info.timestamp_recv;
                        }
                    },
                    None => ()
                }
            },
            _ => {  // ReportFormat::Raw && ReportFormat::Verbose
                let mut dump_packet = self.format_packet(packet);

                self.data.append(&mut Vec::from("----------------\n"));
                self.data.append(&mut dump_packet);
            }
        }
    }

    /// `Format Packet` depending on the report format specifier
    fn format_packet(&self, packet: &str) -> Vec<u8> {
        let ether_packet = EthernetPacket::from_json(&packet).unwrap();
        Vec::from(format!("{}", ether_packet.display_as(self.report_format.clone())))
    }

    /// `Report Generation` periodically called by the timer thread.
    pub fn generate_report(&mut self) -> Result<usize> {
        let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.file_path.as_path())?;

        match self.report_format {
            ReportFormat::Report => {
                let mut report = String::from(format!("{0: <15} | {1: <15} | {2: <9} | {3: <9} | {4: <15} | {5: <15} | {6: <15} | {7: <35} | {8: <35}\n",
                "IP src", "IP dst", "Port src", "Port dst", "L4 Protocol", "Upper Service", "Num. Bytes", "Initial Timestamp", "Final Timestamp").as_str());

                self.data_format.iter_mut().for_each(|(_, value)| { report.push_str(format!("{}\n", value).as_str())});

                let char_num = file.write(report.as_ref())?;

                self.data_format.clear();

                println!("Printing data for report");
                Ok(char_num)
            },
            _ => {
                let char_num = file.write(self.data.as_slice())?;
                self.data.clear();
                println!("Printing data into file");
                Ok(char_num)
            }
        }
    }

    /// `Key Generation` based on a set of packet characteristics (IPs, Ports, L4 protocol)
    pub fn key_gen(&self, re_info: ReportDataInfo) -> String {
        String::from(format!("{} {} {} {} {} {}",
            re_info.ip_src,
            re_info.ip_dst,
            re_info.port_src,
            re_info.port_dst,
            re_info.l4_protocol,
            re_info.upper_service,
        ))
    }

    /// `Apply Filter` searching in the key for keywords inside the packet_filter specified in configuration phase
    fn apply_filter(&self, key: &str) -> bool {
        for filter in self.packet_filter.split_whitespace() {
            let mut found = false;
            for elem in key.split_whitespace() {
                if filter == elem {
                    found = true;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }
}

/// `Report Generator` struct to handle a periodic report generation in a multithreaded environment.
/// Implements a RAII paradigm, allowing a simple instantiation and nothing else.
///
/// # Example
/// ```
/// let report_generator = ReportGenerator::new(file_path, time_interval, report_format, packet_filter, stop_thread, stop_thread_cv).unwrap();
/// // Instantiation and automatic timer activation. When the timer fires everything pushed inside report_generator is logged in the report with the specified format.
///
/// report_generator.push(&packet1);
/// report_generator.push(&packet2);
/// report_generator.push(&packet3);
/// report_generator.push(&packet4);
/// ```
pub struct ReportGenerator {
    /// Inner struct to handle inner mutability in a thread-safe environment of the report generation
    inner_struct: Arc<Mutex<InnerReportGenerator>>,
    /// Timer thread. Periodically calls for a report generation
    timer_thread: Option<JoinHandle<()>>,
    end_thread: Arc<Mutex<bool>>,
}

impl ReportGenerator {
    /// `new`
    pub fn new(config_options: ConfigOptions, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator> {
        let end_thread = Arc::new(Mutex::new(false));
        let end_thread2 = end_thread.clone();

        let inner_struct = Arc::new(Mutex::new(InnerReportGenerator::new(config_options).unwrap()));

        let mut report_generator = Self {
            inner_struct,
            timer_thread: None,
            end_thread
        };

        report_generator.activate(stop_thread, stop_thread_cv, end_thread2);

        Ok(report_generator)
    }

    /// `activate` thread for periodic report generation (timer)
    pub fn activate(&mut self, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>, end_thread: Arc<Mutex<bool>>) {
        let clone_inner_report_generator = self.inner_struct.clone();
        let time_interval = clone_inner_report_generator.lock().unwrap().time_interval;

        self.timer_thread = Option::from(thread::spawn(move || {
            let mut count = 0;
            loop {
                if *end_thread.lock().unwrap() == true { return; }
                let mut stop_flag = *stop_thread.lock().unwrap();
                while stop_flag == true {
                    stop_flag = *stop_thread_cv.wait(stop_thread.lock().unwrap()).unwrap();
                }

                thread::sleep(Duration::from_secs(1));
                count += 1;
                if count == time_interval.as_secs() && *end_thread.lock().unwrap() != true && *stop_thread.lock().unwrap() != true {
                    clone_inner_report_generator.lock().unwrap().generate_report().unwrap();
                    count = 0;
                }
            }
        }))
    }

    /// `push` inside struct data. Used in the report when the timer fires.
    pub fn push(&mut self, packet: &str) {
        self.inner_struct.lock().unwrap().push(packet);
    }

}

impl Drop for ReportGenerator {
    fn drop(&mut self) {
        *self.end_thread.lock().unwrap() = true;
        match self.timer_thread.take() {
            Some(res) => {
                match res.join() {
                    Ok(_) => (),
                    Err(_) => (),
                }
            },
            None => (),
        };
    }
}
