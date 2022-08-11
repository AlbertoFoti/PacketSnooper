//! # Report Generator
//!
//! Module to handle periodic report generation about the traffic analyzed.
//!

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::io::{Write};
use std::path::{PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use crate::{EthernetPacket};
use std::time::{Duration};
use std::thread;
use std::thread::JoinHandle;
use chrono::{DateTime, Utc};

mod tests;

#[derive(Debug, PartialEq)]
/// Report Generator custom Error type RGError.
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
pub enum ReportFormat {
    Raw,
    Verbose,
    Report,
}

#[derive(Debug, Clone)]
pub struct ReportDataInfo {
    pub ip_src: String,
    pub ip_dst: String,
    pub port_src: u16,
    pub port_dst: u16,
    pub l4_protocol: String,
    pub upper_service: String,
    pub num_bytes: usize,
    pub timestamp_recv: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ReportEntry {
    pub ip_src: String,
    pub ip_dst: String,
    pub port_src: u16,
    pub port_dst: u16,
    pub l4_protocol: String,
    pub upper_service: String,
    pub num_bytes: usize,
    pub timestamp_init: DateTime<Utc>,
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

pub trait DisplayAs {
    fn display_as(&self, report_format: ReportFormat) -> String;
}

pub struct InnerReportGenerator {
    file_path: PathBuf,
    time_interval: u64,
    report_format: ReportFormat,
    packet_filter: String,

    data: Vec<u8>,
    data_format: HashMap<String, ReportEntry>,
}

impl InnerReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64, report_format: ReportFormat, packet_filter :String) -> Result<Self> {
        Ok(Self {
            file_path,
            time_interval,
            report_format,
            packet_filter,
            data: Vec::new(),
            data_format: HashMap::new(),
        })
    }

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


                        // TODO : filtering (TCP HTTPS 5000)
                        // TODO : all words in filter are in key
                        // TODO:   if apply_filter() { .... } else { return; }
                        let filtri= self.packet_filter.clone();
                        let c = EthernetPacket::from_json(&packet).unwrap().report_data().unwrap();
                        if self.apply_filter(EthernetPacket::from_json(&packet).unwrap().report_data().unwrap()) {
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

    fn format_packet(&self, packet: &str) -> Vec<u8> {
        let ether_packet = EthernetPacket::from_json(&packet).unwrap();
        Vec::from(format!("{}", ether_packet.display_as(self.report_format.clone())))
    }

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

                let char_num = file.write(report.as_ref()).unwrap();

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

    fn key_gen(&self, re_info: ReportDataInfo) -> String {
        String::from(format!("{} {} {} {} {} {}",
            re_info.ip_src,
            re_info.ip_dst,
            re_info.port_src,
            re_info.port_dst,
            re_info.l4_protocol,
            re_info.upper_service,
        ))
    }

    fn apply_filter(&self, re_info: ReportDataInfo) -> bool {
        let mut filtri = self.packet_filter.split_whitespace();
        let ip_address = filtri.next().unwrap();
        if ip_address != re_info.ip_src && ip_address != re_info.ip_dst && ip_address != "no req" {
            return false;
        }
        let port_address = filtri.next().unwrap();
        if port_address.parse::<u16>().unwrap() != re_info.port_src && port_address.parse::<u16>().unwrap() != re_info.port_dst && port_address != "no req" {
            return false;
        }
        let protocol_l4 = filtri.next().unwrap();
        if protocol_l4 != re_info.l4_protocol && protocol_l4 != "no req" {
            return false;
        }
        true
    }
}

pub struct ReportGenerator {
    inner_struct: Arc<Mutex<InnerReportGenerator>>,
    counting_thread: Option<JoinHandle<()>>,
    end_thread: Arc<Mutex<bool>>,
}

impl ReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64, report_format: ReportFormat, packet_filter: String, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator> {
        let end_thread = Arc::new(Mutex::new(false));
        let end_thread2 = end_thread.clone();

        let inner_struct = Arc::new(Mutex::new(InnerReportGenerator::new(file_path, time_interval, report_format, packet_filter).unwrap()));

        let mut report_generator = Self {
            inner_struct,
            counting_thread: None,
            end_thread
        };

        report_generator.activate(stop_thread, stop_thread_cv, end_thread2);

        Ok(report_generator)
    }

    pub fn activate(&mut self, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>, end_thread: Arc<Mutex<bool>>) {
        let clone_inner_report_generator = self.inner_struct.clone();
        let time_interval = clone_inner_report_generator.lock().unwrap().time_interval;

        self.counting_thread = Option::from(thread::spawn(move || {
            let mut count = 0;
            loop {
                if *end_thread.lock().unwrap() == true { return; }
                let mut stop_flag = *stop_thread.lock().unwrap();
                while stop_flag == true {
                    stop_flag = *stop_thread_cv.wait(stop_thread.lock().unwrap()).unwrap();
                }

                thread::sleep(Duration::from_secs(1));
                count += 1;
                if count == time_interval && *end_thread.lock().unwrap() != true && *stop_thread.lock().unwrap() != true {
                    clone_inner_report_generator.lock().unwrap().generate_report().unwrap();
                    count = 0;
                }
            }
        }))
    }

    pub fn push(&mut self, packet: &str) {
        self.inner_struct.lock().unwrap().push(packet);
    }

}

impl Drop for ReportGenerator {
    fn drop(&mut self) {
        *self.end_thread.lock().unwrap() = true;
        match self.counting_thread.take() {
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
