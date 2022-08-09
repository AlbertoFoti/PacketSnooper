//! # Report Generator
//!
//! Module to handle periodic report generation about the traffic analyzed.
//!

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


pub enum Format {
    Raw,
    Verbose,
    Quiet,
}

pub struct InnerReportGenerator {
    file_path: PathBuf,
    time_interval: u64,
    data: Vec<u8>,
}

impl InnerReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64) -> Result<Self> {
        Ok(Self {
            file_path,
            time_interval,
            data: Vec::new(),
        })
    }

    pub fn push(&mut self, packet: &str) {
        let dump_packet = self.format_packet(Format::Verbose, packet);

        self.data.append(&mut Vec::from("\n----------------\n"));
        self.data.append(&mut Vec::from(dump_packet));
    }

    fn format_packet(&self, format: Format, packet: &str) -> Vec<u8> {
        match format {
            Format::Raw => { Vec::from(packet) },
            Format::Verbose => {
                let ether_packet = EthernetPacket::from_json(&packet).unwrap();
                Vec::from(format!("{}", ether_packet).to_string().as_str())
            },
            Format::Quiet => { Vec::new() },
        }
    }

    pub fn generate_report(&mut self) -> Result<usize> {
        let mut x = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.file_path.as_path())?;
        let char_num = x.write(self.data.as_slice())?;

        self.data.clear();
        println!("Printing data into file");
        Ok(char_num)
    }
}

pub struct ReportGenerator {
    inner_struct: Arc<Mutex<InnerReportGenerator>>,
    counting_thread: Option<JoinHandle<()>>,
    end_thread: Arc<Mutex<bool>>,
}

impl ReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64, stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator> {
        let end_thread = Arc::new(Mutex::new(false));
        let end_thread2 = end_thread.clone();

        let inner_struct = Arc::new(Mutex::new(InnerReportGenerator::new(file_path, time_interval).unwrap()));

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
                if count == clone_inner_report_generator.lock().unwrap().time_interval && *end_thread.lock().unwrap() != true && *stop_thread.lock().unwrap() != true {
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
