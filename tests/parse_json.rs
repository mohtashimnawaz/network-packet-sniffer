use etherparse::PacketBuilder;

#[test]
fn test_json_from_generated_ipv4_tcp_packet() {
    // Build a minimal Ethernet+IPv4+TCP packet
    let mut buf = Vec::with_capacity(1500);

    let builder = PacketBuilder::ethernet2([0x02,0,0,0,0,1], [0x02,0,0,0,0,2])
        .ipv4([192,0,2,1], [198,51,100,2], 64)
        .tcp(12345, 80, 1, 1);

    builder.write(&mut buf, &[]).unwrap();

    // Use the library helper to get JSON and assert expected fields
    let json = network_packet_sniffer::json_from_bytes(buf.len() as u32, 1, 0, &buf);

    assert_eq!(json["net_proto"], "IPv4");
    assert_eq!(json["src"], "192.0.2.1");
    assert_eq!(json["dst"], "198.51.100.2");
    assert_eq!(json["transport_proto"], "TCP");
    assert_eq!(json["sport"], 12345);
    assert_eq!(json["dport"], 80);
}
