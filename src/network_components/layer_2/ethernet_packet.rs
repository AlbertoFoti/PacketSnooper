use chrono::{DateTime, Utc};
use crate::network_components::layer_2::mac_address::MacAddress;
use crate::network_components::layer_3::ipv4_packet::{IPv4Packet, Ipv4ProtocolType};
use crate::network_components::layer_3::ipv6_packet::{Ipv6NextHeader, IPv6Packet};
use serde::{Serialize, Deserialize};
use crate::network_components::services_upper_layers::upper_layer_services::{known_port, UpperLayerService};
use crate::report_generator::{DisplayAs, ReportDataInfo};
use crate::ReportFormat;

#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub enum EtherType {
    Ethernet802_3,
    IPV4,
    IPV6,
    ARP,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EthernetPacket {
    pub mac_addr_dst: MacAddress,
    pub mac_addr_src: MacAddress,
    pub ether_type: Option<EtherType>,
    pub payload: Vec<u8>,
    pub size: usize,
    pub timestamp_recv: DateTime<Utc>,
}

impl EthernetPacket {
    pub fn new(ether_data_in_u8: &[u8]) -> EthernetPacket {
        EthernetPacket {
            mac_addr_dst: MacAddress::new(&ether_data_in_u8[0..6]),
            mac_addr_src: MacAddress::new(&ether_data_in_u8[6..12]),
            ether_type: EthernetPacket::to_ether_type(&ether_data_in_u8[12..14]),
            payload: Vec::from(&ether_data_in_u8[14..]),
            size: ether_data_in_u8.len(),
            timestamp_recv: Utc::now(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(json: &str) -> Result<EthernetPacket, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn report_data(&self) -> Option<ReportDataInfo> {
        #[allow(unused_assignments)]
        let mut ip_src = String::new();
        #[allow(unused_assignments)]
        let mut ip_dst = String::new();
        #[allow(unused_assignments)]
        let mut port_src = 0;
        #[allow(unused_assignments)]
        let mut port_dst = 0;
        let l4_protocol;
        let upper_service;

        match self.ether_type {
            Some(EtherType::Ethernet802_3) => { return None; },
            Some(EtherType::IPV4) => {
                let ipv4_packet = IPv4Packet::new(&self.payload);
                ip_src = ipv4_packet.ip_addr_src.to_string();
                ip_dst = ipv4_packet.ip_addr_dst.to_string();

                (port_src, port_dst) = self.ports(&ipv4_packet.payload);

                l4_protocol = self.l4_protocol(&self.payload);
                if l4_protocol.is_none() { return None; }

                upper_service = self.upper_layer_service(&ipv4_packet.payload);
                if upper_service.is_none() { return None; }
            },
            Some(EtherType::IPV6) => {
                let ipv6_packet = IPv6Packet::new(self.payload.as_slice());
                ip_src = ipv6_packet.ip_addr_src.to_string();
                ip_dst = ipv6_packet.ip_addr_src.to_string();

                (port_src, port_dst) = self.ports(&ipv6_packet.payload);

                l4_protocol = self.l4_protocol(&self.payload);
                if l4_protocol.is_none() { return None; }

                upper_service = self.upper_layer_service(&ipv6_packet.payload);
                if upper_service.is_none() { return None; }
            },
            Some(EtherType::ARP) => { return None; },
            _ => { return None; }
        };

        Some(
            ReportDataInfo {
                ip_src, ip_dst,
                port_src, port_dst,
                l4_protocol: l4_protocol.unwrap(),
                upper_service: upper_service.unwrap(),
                num_bytes: self.size,
                timestamp_recv: self.timestamp_recv,
            } )
    }

    fn to_ether_type(ether_type_in_u8: &[u8]) -> Option<EtherType> {
        match ether_type_in_u8 {
            [x, _] if *x <= 5 => { Some(EtherType::Ethernet802_3) },
            [8, 0] => return Some(EtherType::IPV4),
            [8, 6] => return Some(EtherType::ARP),
            [134, 221] => return Some(EtherType::IPV6),
            x => {
                return {
                    println!("no info on this protocol: {:?}", x);
                    None
                }
            }
        }
    }

    fn ports(&self, payload_in_u8: &[u8] ) -> (u16, u16) {
        let src_port = u16::from_be_bytes((&payload_in_u8[0..2]).try_into().unwrap());
        let dst_port = u16::from_be_bytes((&payload_in_u8[2..4]).try_into().unwrap());
        (src_port,dst_port)
    }

    fn l4_protocol(&self, payload_in_u8: &[u8] ) -> Option<String> {
        match self.ether_type.unwrap() {
            EtherType::IPV4 => {
                let ipv4_packet = IPv4Packet::new(&payload_in_u8);
                match ipv4_packet.protocol_type {
                    Some(Ipv4ProtocolType::TCP) => { Some("TCP".to_string()) },
                    Some(Ipv4ProtocolType::UDP) => { Some("UDP".to_string()) }
                    _ => { None }
                }
            },
            EtherType::IPV6 => {
                let ipv6_packet = IPv6Packet::new(&payload_in_u8);
                match ipv6_packet.next_header.unwrap() {
                    Ipv6NextHeader::TCP => { Some("TCP".to_string()) },
                    Ipv6NextHeader::UDP => { Some("UDP".to_string()) }
                    Ipv6NextHeader::IPv6HopByHopOption => {
                        match ipv6_packet.payload.get(0) {
                            Some(x) => {
                                let next_header = IPv6Packet::to_protocol_type(*x);
                                match next_header {
                                    Some(Ipv6NextHeader::UDP) => { Some("UDP".to_string()) },
                                    Some(Ipv6NextHeader::TCP) => { Some("TCP".to_string()) },
                                    _ => { None }
                                }
                            }, None => { None }
                        }
                    }
                    _ => { None }
                }
            },
            _ => { None }
        }
    }

    fn upper_layer_service(&self, payload_in_u8: &[u8] ) -> Option<String> {
        let (port_src, port_dst) = self.ports(payload_in_u8);
        match UpperLayerService::from(known_port(port_src, port_dst)) {
            UpperLayerService::UNKNOWN => { None },
            service => {
                Some(format!("{:?}", service).to_string())
            }
        }
    }
}

unsafe impl Send for EthernetPacket {}

impl DisplayAs for EthernetPacket {
    fn display_as(&self, report_format: ReportFormat) -> String {
        let mut res = String::new();

        match report_format {
            ReportFormat::Raw => {
                res.push_str("Ethernet ");
                res.push_str( format!("{:?} ", self.ether_type.unwrap()).as_str());

                match self.ether_type {
                    Some(EtherType::Ethernet802_3) => { res.push_str("Ethernet 802.3 : Unknown Details") },
                    Some(EtherType::IPV4) => { res.push_str(format!("{:?}", IPv4Packet::new(self.payload.as_slice()).protocol_type.unwrap()).as_str()) },
                    Some(EtherType::IPV6) => { res.push_str(format!("{:?}", IPv6Packet::new(self.payload.as_slice()).next_header.unwrap()).as_str()) },
                    Some(EtherType::ARP) => { res.push_str( "ARP      : Unknown Details") },
                    _ => { res.push_str("Other Protocol incapsulated in Ethernet frame (Unknown Protocol)") }
                };
                res.push('\n');
                res
            },
            ReportFormat::Verbose => {
                res.push_str("Ethernet ");
                res.push_str(format!(": {} -> {} \n", self.mac_addr_dst, self.mac_addr_src).as_str());

                match self.ether_type {
                    Some(EtherType::Ethernet802_3) => { res.push_str("Ethernet 802.3 : Unknown Details") },
                    Some(EtherType::IPV4) => { res.push_str(format!("{}", IPv4Packet::new(self.payload.as_slice())).as_str()) },
                    Some(EtherType::IPV6) => { res.push_str(format!("{}", IPv6Packet::new(self.payload.as_slice())).as_str()) },
                    Some(EtherType::ARP) => { res.push_str( "ARP      : Unknown Details") },
                    _ => { res.push_str("Other Protocol incapsulated in Ethernet frame (Unknown Protocol)") }
                };
                res.push('\n');
                res
            },
            ReportFormat::Report => {
                res.push_str("Printing format for report");
                res
            }
        }
    }
}
