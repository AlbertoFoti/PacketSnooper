use pcap::Device;
use crate::PacketSnooper;

#[cfg(test)]
pub mod packet_snooper_tests;

#[cfg(test)]
pub mod configuration_tests;

#[cfg(test)]
pub mod state_machine_tests;

#[cfg(test)]
pub fn complete_setup() -> PacketSnooper {
    let interface_name = Device::lookup().unwrap().name;
    let time_interval = 75;
    let file_path = "hello.txt";

    PacketSnooper::new().with_details(
        interface_name.as_str(),
        time_interval,
        file_path,
    ).unwrap()
}





