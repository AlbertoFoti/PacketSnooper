use packet_snooper::packet_snooper;

fn main() {
    packet_snooper::print_interfaces();

    packet_snooper::test_simple_read_packets();
}
