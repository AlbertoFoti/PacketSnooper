use PacketSnooper::PacketSnooper;

fn main() {

    PacketSnooper::print_interfaces();

    PacketSnooper::test_simple_read_packets();
}