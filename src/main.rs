use pcap::Device;

fn main() {
    println!("Hello, world!");

    let devices = Device::list().unwrap();

    for device in devices {
        println!("Device name: {}", device.name);
    }
}
