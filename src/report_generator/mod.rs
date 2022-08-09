//! # Report Generator
//!
//! Module to handle periodic report generation about the traffic analyzed.
//!

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::{fs, io};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use crate::EthernetPacket;
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

pub struct PeriodicTimer {
    time_interval: u64,
    counting_thread: Option<JoinHandle<()>>,
    end_thread: Arc<Mutex<bool>>
}

impl PeriodicTimer {
    pub fn new(time_interval: u64) -> Self {
        let end_thread = Arc::new(Mutex::new(false));
        let end_thread2 = end_thread.clone();

        Self {
            time_interval,
            counting_thread: Option::from(thread::spawn(move || {
                let mut i = 0;
                loop {
                    println!("Elapsed time {}", i);
                    thread::sleep(Duration::from_secs(1));
                    i += 1;
                    if *end_thread2.lock().unwrap() == true { return; }
                }
                println!("Ending periodic timer thread");
            })),
            end_thread,
        }
    }
}

impl Drop for PeriodicTimer {
    fn drop(&mut self) {
        *self.end_thread.lock().unwrap() = true;
        self.counting_thread.take().map(JoinHandle::join).unwrap();
        println!("Dropping Periodic timer.")
    }
}

pub enum Format {
    Raw,
    Verbose,
    Quiet,
}

pub struct ReportGenerator {
    file_path: PathBuf,
    timer: PeriodicTimer,
    data: Vec<u8>,
}

impl ReportGenerator {
    pub fn new(file_path: PathBuf, time_interval: u64) -> Result<Self> {
        Ok(Self {
            file_path,
            timer: PeriodicTimer::new(time_interval),
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
            Format::Raw=> { Vec::from(packet) },
            Format::Verbose => {
                let ether_packet = EthernetPacket::from_json(&packet).unwrap();
                Vec::from(format!("{}", ether_packet).to_string().as_str())
            },
            Format::Quiet => { Vec::new() },
        }
    }

    fn generate_report(&mut self) -> Result<()> {
        // TODO: handle error cases better
        let mut x = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.file_path.as_path()).expect("Something went wrong while creating the file for report generation.");
        let y = x.write(self.data.as_slice()).expect("Something went wrong during the report generation file write.");

        self.data.clear();
        Ok(())
    }
}

impl Drop for ReportGenerator {
    fn drop(&mut self) {
        println!("Dropping Report Generator...");
    }
}
