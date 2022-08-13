use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::Duration;
use pcap::Device;
use crate::report_generator::RGError;
use crate::{ConfigOptions, EthernetPacket, ReportFormat, ReportGenerator};
use crate::report_generator::tests::{PACKET, PACKET2, PACKET3, PACKET_SIZE};

pub fn create_report_generator(stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator, RGError> {
    let options = ConfigOptions::new(
        Device::lookup().unwrap().name.as_str(),
        15,
        "output.txt",
        ReportFormat::Report,
        "UDP");

    ReportGenerator::new(options, stop_thread, stop_thread_cv)
}

pub fn create_report_generator2(stop_thread: Arc<Mutex<bool>>, stop_thread_cv: Arc<Condvar>) -> Result<ReportGenerator, RGError> {
    let options = ConfigOptions::new(
        Device::lookup().unwrap().name.as_str(),
        3,
        "output.txt",
        ReportFormat::Report,
        "UDP");

    ReportGenerator::new(options, stop_thread, stop_thread_cv)
}

#[test]
pub fn report_generator_new_test() {
    let stop_thread = Arc::new(Mutex::new(false));
    let stop_thread_cv = Arc::new(Condvar::new());

    let res = create_report_generator(stop_thread.clone(), stop_thread_cv.clone());
    assert!(res.is_ok());
    let report_generator = res.unwrap();
    assert_eq!(*report_generator.end_thread.lock().unwrap(), false);
    assert!(report_generator.timer_thread.is_some());
}

#[test]
pub fn push_test() {
    let stop_thread = Arc::new(Mutex::new(false));
    let stop_thread_cv = Arc::new(Condvar::new());

    let mut report_generator = create_report_generator(stop_thread.clone(), stop_thread_cv.clone()).unwrap();
    report_generator.push(PACKET);
    report_generator.push(PACKET2);
    report_generator.push(PACKET3);
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.len(), 3);
}

#[test]
pub fn push_test2() {
    let stop_thread = Arc::new(Mutex::new(false));
    let stop_thread_cv = Arc::new(Condvar::new());

    let mut report_generator = create_report_generator(stop_thread.clone(), stop_thread_cv.clone()).unwrap();
    report_generator.push(PACKET);
    report_generator.push(PACKET);
    report_generator.push(PACKET);
    report_generator.push(PACKET);
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.len(), 1);

    let rg_info = EthernetPacket::from_json(PACKET).unwrap().report_data().unwrap();
    let key = report_generator.inner_struct.lock().unwrap().key_gen(rg_info);
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.get_key_value(key.as_str()).unwrap().1.num_bytes, 4*PACKET_SIZE);
}

#[test]
pub fn generate_report_test() {
    let stop_thread = Arc::new(Mutex::new(false));
    let stop_thread_cv = Arc::new(Condvar::new());

    let mut report_generator = create_report_generator2(stop_thread.clone(), stop_thread_cv.clone()).unwrap();
    report_generator.push(PACKET);
    sleep(Duration::from_secs(4));
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.len(), 0); // Data flushed
}

#[test]
pub fn timer_thread_stopped_test() {
    let stop_thread = Arc::new(Mutex::new(false));
    let stop_thread_cv = Arc::new(Condvar::new());

    let mut report_generator = create_report_generator2(stop_thread.clone(), stop_thread_cv.clone()).unwrap();
    report_generator.push(PACKET);

    *stop_thread.lock().unwrap() = true;
    sleep(Duration::from_secs(4));
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.len(), 1);

    *stop_thread.lock().unwrap() = false;
    stop_thread_cv.notify_all();
    sleep(Duration::from_secs(4));
    assert_eq!(report_generator.inner_struct.lock().unwrap().data_format.len(), 0);
}


