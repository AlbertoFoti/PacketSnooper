use rustcap::core::*;

fn main() {
    println!("Hello, world!");

    let something = rustcap::core::create("wlp3s0").unwrap();
    println!("{:?}", something.datalink());
}
