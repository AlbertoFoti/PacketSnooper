use crate::network_components::upper_layer_services::{to_upper_layer_service, UpperLayerService};

#[test]
pub fn to_upper_layer_services_test() {
    assert_eq!(to_upper_layer_service(20, 4567).unwrap(), UpperLayerService::FTP);
    assert_eq!(to_upper_layer_service(4567, 20).unwrap(), UpperLayerService::FTP);

    assert_eq!(to_upper_layer_service(22, 4567).unwrap(), UpperLayerService::SSH);
    assert_eq!(to_upper_layer_service(4567, 22).unwrap(), UpperLayerService::SSH);

    assert_eq!(to_upper_layer_service(23, 4567).unwrap(), UpperLayerService::SMTP);
    assert_eq!(to_upper_layer_service(4567, 23).unwrap(), UpperLayerService::SMTP);

    assert_eq!(to_upper_layer_service(53, 4567).unwrap(), UpperLayerService::DNS);
    assert_eq!(to_upper_layer_service(4567, 53).unwrap(), UpperLayerService::DNS);

    assert_eq!(to_upper_layer_service(80, 4567).unwrap(), UpperLayerService::HTTP);
    assert_eq!(to_upper_layer_service(4567, 80).unwrap(), UpperLayerService::HTTP);

    assert_eq!(to_upper_layer_service(110, 4567).unwrap(), UpperLayerService::POP3);
    assert_eq!(to_upper_layer_service(4567, 110).unwrap(), UpperLayerService::POP3);

    assert_eq!(to_upper_layer_service(115, 4567).unwrap(), UpperLayerService::SFTP);
    assert_eq!(to_upper_layer_service(4567, 115).unwrap(), UpperLayerService::SFTP);

    assert_eq!(to_upper_layer_service(161, 4567).unwrap(), UpperLayerService::SNMP);
    assert_eq!(to_upper_layer_service(4567, 161).unwrap(), UpperLayerService::SNMP);

    assert_eq!(to_upper_layer_service(179, 4567).unwrap(), UpperLayerService::BGP);
    assert_eq!(to_upper_layer_service(4567, 179).unwrap(), UpperLayerService::BGP);

    assert_eq!(to_upper_layer_service(443, 4567).unwrap(), UpperLayerService::HTTPS);
    assert_eq!(to_upper_layer_service(4567, 443).unwrap(), UpperLayerService::HTTPS);
}

#[test]
pub fn to_upper_layer_service_not_well_known() {
    assert_eq!(to_upper_layer_service(2000, 2000).is_none(), true);
}

#[test]
pub fn to_upper_layer_service_unknown_protocol() {
    assert_eq!(to_upper_layer_service(1023, 2000).is_none(), true);
    assert_eq!(to_upper_layer_service(2000, 1023).is_none(), true);
}