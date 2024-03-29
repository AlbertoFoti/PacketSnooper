use std::thread::{JoinHandle, sleep};
use std::time::Duration;
use crate::{PacketSnooper, State};
use crate::tests::complete_setup;

#[test]
pub fn packet_snooper_start_normal_test() {
    let mut ps = complete_setup();

    assert_eq!(ps.state, State::Ready);
    ps.start().unwrap();

    assert_eq!(ps.state, State::Working);
    assert!(ps.network_capture_thread.is_some());
    assert!(ps.consumer_thread.is_some());
    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);
}

#[test]
pub fn packet_snooper_start_in_invalid_state_test() {
    let error_str = "Invalid call on start when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::Working, State::Stopped];
    let valid_states = [State::Ready];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.start();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.start();
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_stop_normal_test() {
    let mut ps = complete_setup();

    ps.start().unwrap();
    ps.stop().unwrap();

    assert_eq!(ps.state, State::Stopped);
    assert!(ps.network_capture_thread.is_some());
    assert!(ps.consumer_thread.is_some());
    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), true);
}

#[test]
pub fn packet_snooper_stop_in_invalid_state_test() {
    let error_str = "Invalid call on stop when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::Ready, State::Stopped];
    let valid_states = [State::Working];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.stop();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.stop();
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_resume_normal_test() {
    let mut ps = complete_setup();

    ps.start().unwrap();
    ps.stop().unwrap();
    ps.resume().unwrap();

    assert_eq!(ps.state, State::Working);
    assert!(ps.network_capture_thread.is_some());
    assert!(ps.consumer_thread.is_some());
    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);
}

#[test]
pub fn packet_snooper_resume_in_invalid_state_test() {
    let error_str = "Invalid call on resume when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::Ready, State::Working];
    let valid_states = [State::Stopped];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.resume();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.resume();
        assert!(res.is_ok());
    }
}

#[test]
pub fn packet_snooper_end_normal_test() {
    let mut ps = complete_setup();

    ps.start().unwrap();
    ps.end().unwrap();

    assert_eq!(ps.state, State::Ready);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), true);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    ps.start().unwrap();
    ps.stop().unwrap();
    ps.end().unwrap();

    assert_eq!(ps.state, State::Ready);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), true);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);
}

#[test]
pub fn packet_snooper_end_in_invalid_state_test() {
    let error_str = "Invalid call on end when in an illegal state.";
    let mut ps = PacketSnooper::new();

    let invalid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::Ready];
    let valid_states = [State::Working, State::Stopped];

    for state in invalid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.end();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().message, error_str);
    }

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        let res = ps.end();
        assert!(res.is_ok());
        assert_eq!(ps.state, State::Ready);
    }
}

#[test]
pub fn packet_snooper_rapid_end_test() {
    let mut ps = complete_setup();

    let mut i = 5;
    while i > 0 {
        ps.start().unwrap();
        ps.end().unwrap();
        i -= 1;
    }
}

#[test]
pub fn packet_snooper_abort_normal_test() {
    let mut ps = complete_setup();
    sleep(Duration::from_secs(1));
    ps.start().unwrap();
    sleep(Duration::from_secs(1));
    ps.abort().unwrap();
    sleep(Duration::from_secs(1));

    assert_eq!(ps.state, State::ConfigDevice);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), true);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    sleep(Duration::from_secs(1));
    let mut ps = complete_setup();
    ps.start().unwrap();
    sleep(Duration::from_secs(1));
    ps.stop().unwrap();
    sleep(Duration::from_secs(1));
    ps.abort().unwrap();
    sleep(Duration::from_secs(1));

    assert_eq!(ps.state, State::ConfigDevice);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), true);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);
}

#[test]
pub fn packet_snooper_abort_in_config_state_test() {
    let mut ps = PacketSnooper::new();

    assert_eq!(ps.state, State::ConfigDevice);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), false);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    ps.abort().unwrap();

    assert_eq!(ps.state, State::ConfigDevice);
    assert!(ps.network_capture_thread.is_none());
    assert!(ps.consumer_thread.is_none());
    assert_eq!(*ps.end_thread.lock().unwrap(), true);
    assert_eq!(*ps.stop_thread.lock().unwrap(), false);

    let x = ps.network_capture_thread.take().map(JoinHandle::join);
    assert!(x.is_none());

}

#[test]
pub fn packet_snooper_abort_in_invalid_state_test() {
    let mut ps = PacketSnooper::new();

    let valid_states = [State::ConfigDevice, State::ConfigTimeInterval, State::ConfigFile, State::Ready, State::Working, State::Stopped];

    for state in valid_states {
        ps.state = state; // forcing packet_snooper into a specific state (not safe, just for testing purposes)
        ps.abort().unwrap();
        assert_eq!(ps.state, State::ConfigDevice);
    }
}

#[test]
pub fn packet_snooper_rapid_abort_test() {
    let mut i = 5;
    while i > 0 {
        let mut ps = complete_setup();
        ps.start().unwrap();
        ps.abort().unwrap();
        i -= 1;
    }
}
