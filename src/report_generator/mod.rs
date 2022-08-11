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
use std::time::{Duration, Instant};
use std::thread;
use std::thread::JoinHandle;

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
    //pub port_src: u16,
    //pub port_dst: u16,
    //pub l4_protocol: String,
    //pub upper_service: String,
    pub num_bytes: usize,
    pub timestamp_recv: Instant,
}

#[derive(Debug, Clone, Copy)]
pub struct ReportEntry {
    pub num_bytes: usize,
    pub timestamp_init: Instant,
    pub timestamp_final: Instant,
}

pub trait DisplayAs {
    fn display_as(&self, report_format: ReportFormat) -> String;
}

pub struct InnerReportGenerator {
    file_path: PathBuf,
    time_interval: u64,
    report_format: ReportFormat,

    data: Vec<u8>,
    data_format: HashMap<String, ReportEntry>,
}

impl InnerReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64, report_format: ReportFormat) -> Result<Self> {
        Ok(Self {
            file_path,
            time_interval,
            report_format,
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
                        //println!("{:?}", key);

                        // add to hash map
                        let value = ReportEntry { num_bytes: 0, timestamp_init: rg_info.timestamp_recv, timestamp_final: rg_info.timestamp_recv };
                        let entry = self.data_format.entry(key).or_insert(value);
                        entry.num_bytes += rg_info.num_bytes;
                        entry.timestamp_final = rg_info.timestamp_recv;
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
                let mut x = String::new();
                for (key, value) in self.data_format.iter_mut() {
                    let mut s = String::new();
                    for elem in key.split_whitespace() {
                        s.push_str(format!("{} | ", elem).as_str());
                    }
                    s.push_str(format!("{:?}\n", value).as_str());
                    x.push_str(s.as_str());
                }
                let char_num = file.write(x.as_ref()).unwrap();
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
        String::from(format!("{} {}",
            re_info.ip_src,
            re_info.ip_dst))
    }
}

pub struct ReportGenerator {
    inner_struct: Arc<Mutex<InnerReportGenerator>>,
    counting_thread: Option<JoinHandle<()>>,
    end_thread: Arc<Mutex<bool>>,
}

impl ReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64, report_format: ReportFormat , stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator> {
        let end_thread = Arc::new(Mutex::new(false));
        let end_thread2 = end_thread.clone();

        let inner_struct = Arc::new(Mutex::new(InnerReportGenerator::new(file_path, time_interval, report_format).unwrap()));

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
