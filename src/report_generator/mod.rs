use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::Write;
use crate::EthernetPacket;

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

pub struct ReportGenerator {

}

impl ReportGenerator {
    pub fn new(time_interval: u64, file_path: &str) -> Result<Self> {
        Ok(Self {})
    }

    pub fn push(&mut self, packet: &str) {
        println!("---------------");
        println!("{}", EthernetPacket::from_json(&packet).unwrap());
        io::stdout().flush().unwrap();
    }

    fn generate_report(&self) -> Result<()> {
        Ok(())
    }
}

impl Drop for ReportGenerator {
    fn drop(&mut self) {

    }
}
