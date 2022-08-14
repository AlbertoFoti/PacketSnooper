use std::path::PathBuf;
use std::time::Duration;
use pcap::Device;
use crate::{ConfigOptions, EthernetPacket, ReportFormat};
use crate::report_generator::{InnerReportGenerator, RGError};
use crate::report_generator::tests::PACKET;

pub fn create_report_generator_inner() -> Result<InnerReportGenerator, RGError> {
    let options = ConfigOptions::new(
        Device::lookup().unwrap().name.as_str(),
        75,
        "output.txt",
        ReportFormat::Report,
        "UDP");

    InnerReportGenerator::new(options)
}

#[test]
pub fn report_generator_new_test() {
    let inner_report_generator = create_report_generator_inner();
    assert!(inner_report_generator.is_ok());
    let inner_report_generator = inner_report_generator.unwrap();
    assert_eq!(inner_report_generator.time_interval, Duration::from_secs(75));
    assert_eq!(inner_report_generator.file_path, PathBuf::from("output.txt"));
    assert_eq!(inner_report_generator.report_format, ReportFormat::Report);
    assert_eq!(inner_report_generator.packet_filter, "UDP".to_string());
    assert!(inner_report_generator.data.is_empty());
    assert!(inner_report_generator.data_format.is_empty());
}

#[test]
pub fn push_test() {
    let mut inner_report_generator = create_report_generator_inner().unwrap();

    inner_report_generator.push(PACKET);

    assert_eq!(inner_report_generator.data_format.len(), 1);
}

#[test]
pub fn key_gen_normal_test() {
    let rg_info = EthernetPacket::from_json(PACKET).unwrap().report_data().unwrap();

    let inner_report_generator = create_report_generator_inner().unwrap();
    let res = inner_report_generator.key_gen(rg_info);
    let expected = "142.250.184.67 192.168.1.119 443 45087 UDP HTTPS";

    assert_eq!(res, expected.to_string());
}

#[test]
pub fn key_gen_normal_test_2() {
    let mut rg_info = EthernetPacket::from_json(PACKET).unwrap().report_data().unwrap();
    rg_info.ip_src = "0.0.0.0".to_string();
    rg_info.port_src = 50000;
    rg_info.upper_service = "DNS".to_string();

    let inner_report_generator = create_report_generator_inner().unwrap();
    let res = inner_report_generator.key_gen(rg_info);
    let expected = "0.0.0.0 192.168.1.119 50000 45087 UDP DNS";

    assert_eq!(res, expected.to_string());
}

#[test]
pub fn apply_filter_normal_test() {
    assert_eq!(1, 1)
}

#[test]
pub fn apply_filter_normal_test_2() {
    assert_eq!(1, 1)
}