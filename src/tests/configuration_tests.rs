use std::path::PathBuf;
use std::time::Duration;
use pcap::Device;
use crate::{PacketSnooper, State};

#[test]
pub fn packet_snooper_set_device_normal_test() {
    let interface_name = Device::lookup().unwrap().name;
    let mut ps = PacketSnooper::new();

    assert_eq!(ps.state, State::ConfigDevice);

    ps.set_device(interface_name.as_str()).unwrap();

    assert_eq!(ps.state, State::ConfigTimeInterval);
    assert_eq!(ps.current_interface, interface_name);
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
    assert_ne!(ps.current_interface, interface_name);
}

#[test]
pub fn packet_snooper_set_device_in_invalid_state_test() {
    let interface_name = Device::lookup().unwrap().name;
    let error_str = "Invalid call on set_device when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigTimeInterval, State::ConfigFile, State::Ready, State::Working, State::Stopped];
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
    assert_eq!(ps.time_interval, Duration::from_secs(time_interval));
}

#[test]
pub fn packet_snooper_set_time_interval_in_invalid_state_test() {
    let time_interval = 75;
    let error_str = "Invalid call on set_time_interval when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigFile, State::Ready, State::Working, State::Stopped];
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
pub fn packet_snooper_set_file_name_interval_normal_test() {
    let file_name = "hello.txt";
    let mut ps = PacketSnooper::new();

    ps.state = State::ConfigFile; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
    assert!(ps.set_file_name(file_name).is_ok());

    assert_eq!(ps.state, State::Ready);
    assert_eq!(ps.file_path, PathBuf::from(file_name));
}

#[test]
pub fn packet_snooper_set_file_name_in_invalid_state_test() {
    let file_name = "hello.txt";
    let error_str = "Invalid call on set_file_name when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::Ready, State::Working, State::Stopped];
    let valid_states = [State::ConfigFile];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_file_name(file_name);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.set_file_name(file_name);
        assert!(res.is_ok());
    }
}
