use crate::network_components::upper_layer_services::{known_port, UpperLayerService};

#[test]
pub fn from_known_port_to_service_test() {
    assert_eq!(UpperLayerService::from(known_port(20, 4567)), UpperLayerService::FTP);
    assert_eq!(UpperLayerService::from(known_port(4567, 20)), UpperLayerService::FTP);

    assert_eq!(UpperLayerService::from(known_port(22, 4567)), UpperLayerService::SSH);
    assert_eq!(UpperLayerService::from(known_port(4567, 22)), UpperLayerService::SSH);

    assert_eq!(UpperLayerService::from(known_port(23, 4567)), UpperLayerService::SMTP);
    assert_eq!(UpperLayerService::from(known_port(4567, 23)), UpperLayerService::SMTP);

    assert_eq!(UpperLayerService::from(known_port(53, 4567)), UpperLayerService::DNS);
    assert_eq!(UpperLayerService::from(known_port(4567, 53)), UpperLayerService::DNS);

    assert_eq!(UpperLayerService::from(known_port(80, 4567)), UpperLayerService::HTTP);
    assert_eq!(UpperLayerService::from(known_port(4567, 80)), UpperLayerService::HTTP);

    assert_eq!(UpperLayerService::from(known_port(110, 4567)), UpperLayerService::POP3);
    assert_eq!(UpperLayerService::from(known_port(4567, 110)), UpperLayerService::POP3);

    assert_eq!(UpperLayerService::from(known_port(115, 4567)), UpperLayerService::SFTP);
    assert_eq!(UpperLayerService::from(known_port(4567, 115)), UpperLayerService::SFTP);

    assert_eq!(UpperLayerService::from(known_port(161, 4567)), UpperLayerService::SNMP);
    assert_eq!(UpperLayerService::from(known_port(4567, 161)), UpperLayerService::SNMP);

    assert_eq!(UpperLayerService::from(known_port(179, 4567)), UpperLayerService::BGP);
    assert_eq!(UpperLayerService::from(known_port(4567, 179)), UpperLayerService::BGP);

    assert_eq!(UpperLayerService::from(known_port(443, 4567)), UpperLayerService::HTTPS);
    assert_eq!(UpperLayerService::from(known_port(4567, 443)), UpperLayerService::HTTPS);
}

#[test]
pub fn from_unknown_port_to_service_test() {
    assert_eq!(UpperLayerService::from(known_port(2000, 2000)), UpperLayerService::UNKNOWN);
}

#[test]
pub fn from_unknown_protocol_to_service_test() {
    assert_eq!(UpperLayerService::from(known_port(1023, 2000)), UpperLayerService::UNKNOWN);
    assert_eq!(UpperLayerService::from(known_port(2000, 1023)), UpperLayerService::UNKNOWN);
}