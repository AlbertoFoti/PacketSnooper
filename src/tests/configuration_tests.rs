use std::path::PathBuf;
use std::time::Duration;
use pcap::Device;
use crate::{PacketSnooper, ReportFormat, State};

#[test]
pub fn packet_snooper_set_device_normal_test() {
    let interface_name = Device::lookup().unwrap().name;
    let mut ps = PacketSnooper::new();

    assert_eq!(ps.state, State::ConfigDevice);

    ps.set_device(interface_name.as_str()).unwrap();

    assert_eq!(ps.state, State::ConfigTimeInterval);
    assert_eq!(ps.config_options.current_interface, interface_name);
}

#[test]
pub fn packet_snooper_set_device_interface_not_found_test() {
    let interface_name = "wrong_interface_name";
    let mut ps = PacketSnooper::new();

    assert_eq!(ps.state, State::ConfigDevice);

    let res = ps.set_device(interface_name);

    assert!(res.is_err());
    let got = res.unwrap_err();
    assert_eq!(got.message, "unable to find device with the specified interface name ");

    assert_eq!(ps.state, State::ConfigDevice);
    assert_ne!(ps.config_options.current_interface, interface_name);
}

#[test]
pub fn packet_snooper_set_device_in_invalid_state_test() {
    let interface_name = Device::lookup().unwrap().name;
    let error_str = "Invalid call on set_device when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigTimeInterval, State::ConfigFile, State::ReportFormat, State::PacketFilter, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::ConfigDevice];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_device(interface_name.as_str());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_device(interface_name.as_str());
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_set_time_interval_normal_test() {
    let time_interval = 75;
    let mut ps = PacketSnooper::new();

    ps.state = State::ConfigTimeInterval; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    assert!(ps.set_time_interval(time_interval).is_ok());

    assert_eq!(ps.state, State::ConfigFile);
    assert_eq!(ps.config_options.time_interval, Duration::from_secs(time_interval));
}

#[test]
pub fn packet_snooper_set_time_interval_in_invalid_state_test() {
    let time_interval = 75;
    let error_str = "Invalid call on set_time_interval when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigFile, State::ReportFormat, State::PacketFilter, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::ConfigTimeInterval];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_time_interval(time_interval);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_time_interval(time_interval);
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_set_file_path_normal_test() {
    let file_path = "hello.txt";
    let mut ps = PacketSnooper::new();

    ps.state = State::ConfigFile; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    assert!(ps.set_file_path(file_path).is_ok());

    assert_eq!(ps.state, State::ReportFormat);
    assert_eq!(ps.config_options.file_path, PathBuf::from(file_path));
}

#[test]
pub fn packet_snooper_set_file_path_in_invalid_state_test() {
    let file_path = "hello.txt";
    let error_str = "Invalid call on set_file_path when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ReportFormat, State::PacketFilter, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::ConfigFile];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_file_path(file_path);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_file_path(file_path);
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_set_report_format_normal_test() {
    let format_report = "report";
    let mut ps = PacketSnooper::new();

    ps.state = State::ReportFormat; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    assert!(ps.set_report_format(format_report).is_ok());

    assert_eq!(ps.state, State::PacketFilter);
    assert_eq!(ps.config_options.report_format, ReportFormat::Report);
}

#[test]
pub fn packet_snooper_set_report_format_in_invalid_state_test() {
    let format_report = "report";
    let error_str = "Invalid call on set_report_format when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::PacketFilter, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::ReportFormat];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_report_format(format_report);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_report_format(format_report);
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_set_packet_filter_normal_test() {
    let packet_filter = "TCP";
    let mut ps = PacketSnooper::new();

    ps.state = State::PacketFilter; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    assert!(ps.set_packet_filter(packet_filter).is_ok());

    assert_eq!(ps.state, State::Ready);
    assert_eq!(ps.config_options.packet_filter, "TCP".to_string());
}

#[test]
pub fn packet_snooper_set_packet_filter_invalid_format_test() {
    let packet_filter = "中國的 ~=[]()%+{}@;";
    let error_str = "Invalid format given as a parameter.";
    let mut ps = PacketSnooper::new();

    ps.state = State::PacketFilter; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    let res = ps.set_packet_filter(packet_filter);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().message, error_str);
    assert_eq!(ps.state, State::PacketFilter);
}

#[test]
pub fn packet_snooper_set_packet_filter_in_invalid_state_test() {
    let packet_filter = "TCP";
    let error_str = "Invalid call on set_packet_filter when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::ReportFormat, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::PacketFilter];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_packet_filter(packet_filter);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_packet_filter(packet_filter);
        assert!(res.is_ok());
    }
}


