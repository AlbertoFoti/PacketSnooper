use std::path::PathBuf;
use std::time::Duration;
use pcap::Device;
use crate::{PacketSnooper, State};

#[test]
pub fn packet_snooper_new_test() {
    let ps = PacketSnooper::new();

    assert_eq!(ps.state, State::ConfigDevice);

    assert_ne!(ps.current_interface.as_str(), "");
    assert_eq!(ps.time_interval, Duration::from_secs(60));
    assert_eq!(ps.file_path, PathBuf::from("output.txt"));

    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    assert_eq!(ps.network_capture_thread.is_none(), true);
    assert_eq!(ps.consumer_thread.is_none(), true);
}

#[test]
pub fn packet_snooper_with_details_test() {
    let interface_name = Device::lookup().unwrap().name;
    let time_interval = 75;
    let file_path = "hello.txt";
    let report_format = "report";
    let packet_filter = "TCP";

    let ps = PacketSnooper::new().with_details(
        interface_name.as_str(),
        time_interval,
        file_path,
        report_format,
        packet_filter,
    ).unwrap();

    assert_eq!(ps.state, State::Ready);

    assert_eq!(ps.current_interface, interface_name);
    assert_eq!(ps.time_interval, Duration::from_secs(time_interval));
    assert_eq!(ps.file_path, PathBuf::from(file_path));

    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    assert_eq!(ps.network_capture_thread.is_none(), true);
    assert_eq!(ps.consumer_thread.is_none(), true);
}
