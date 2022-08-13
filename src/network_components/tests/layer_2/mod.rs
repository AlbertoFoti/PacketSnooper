const PACKET: &'static str = "{\"mac_addr_dst\":{\"mac_raw\":[116,229,249,22,238,155]},\"mac_addr_src\":{\"mac_raw\":[224,185,229,48,239,152]},\"ether_type\":\"IPV4\",\"payload\":[69,0,0,52,61,246,64,0,233,6,236,162,3,93,161,174,192,168,1,119,1,187,215,30,153,191,216,65,30,224,14,36,128,16,0,114,12,83,0,0,1,1,8,10,93,226,9,254,1,227,33,43],\"size\":66,\"timestamp_recv\":\"2022-08-13T09:01:24.713816911Z\",\"report_data\":{\"ip_src\":\"3.93.161.174\",\"ip_dst\":\"192.168.1.119\",\"port_src\":443,\"port_dst\":55070,\"l4_protocol\":\"TCP\",\"upper_service\":\"HTTPS\",\"num_bytes\":66,\"timestamp_recv\":\"2022-08-13T09:01:24.713816911Z\"}}";

#[cfg(test)]
pub mod ethernet_packet_tests;

#[cfg(test)]
pub mod mac_address_tests;
