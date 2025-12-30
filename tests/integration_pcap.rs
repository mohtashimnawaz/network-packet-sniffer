use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use tempfile::tempdir;
use etherparse::PacketBuilder;

#[test]
fn test_pcap_roundtrip_manual_write_and_read() {
    // build a simple Ethernet + IPv4 + UDP packet
    let mut buf = Vec::new();
    let builder = PacketBuilder::ethernet2([0x02,0,0,0,0,1], [0x02,0,0,0,0,2])
        .ipv4([192,0,2,1], [203,0,113,5], 64)
        .udp(55555, 53);
    builder.write(&mut buf, &[]).unwrap();

    // create temp file and write a minimal pcap (little-endian) global header + one packet
    let dir = tempdir().unwrap();
    let path = dir.path().join("test_capture.pcap");
    let mut f = File::create(&path).unwrap();

    // PCAP Global header (little-endian magic 0xd4c3b2a1)
    f.write_all(&0xd4c3b2a1u32.to_le_bytes()).unwrap(); // magic
    f.write_all(&2u16.to_le_bytes()).unwrap(); // version major
    f.write_all(&4u16.to_le_bytes()).unwrap(); // version minor
    f.write_all(&0i32.to_le_bytes()).unwrap(); // thiszone
    f.write_all(&0u32.to_le_bytes()).unwrap(); // sigfigs
    f.write_all(&65535u32.to_le_bytes()).unwrap(); // snaplen
    f.write_all(&1u32.to_le_bytes()).unwrap(); // network = DLT_EN10MB

    // Packet header: use ts=1,0; incl_len=len, orig_len=len
    let len = buf.len() as u32;
    f.write_all(&1u32.to_le_bytes()).unwrap(); // ts_sec
    f.write_all(&0u32.to_le_bytes()).unwrap(); // ts_usec
    f.write_all(&len.to_le_bytes()).unwrap(); // incl_len
    f.write_all(&len.to_le_bytes()).unwrap(); // orig_len

    // Packet bytes
    f.write_all(&buf).unwrap();
    f.flush().unwrap();

    // Read back the file manually and extract the first packet
    let mut fr = File::open(&path).unwrap();
    // skip global header (24 bytes)
    fr.seek(SeekFrom::Start(24)).unwrap();

    let mut phdr = [0u8; 16];
    fr.read_exact(&mut phdr).unwrap();
    let ts_sec = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
    let ts_usec = u32::from_le_bytes(phdr[4..8].try_into().unwrap());
    let incl_len = u32::from_le_bytes(phdr[8..12].try_into().unwrap()) as usize;

    let mut pdata = vec![0u8; incl_len];
    fr.read_exact(&mut pdata).unwrap();

    // Use library helper to parse -> JSON and validate
    let json = network_packet_sniffer::json_from_bytes(incl_len as u32, ts_sec as i64, ts_usec as i64, &pdata);

    assert_eq!(json["net_proto"], "IPv4");
    assert_eq!(json["src"], "192.0.2.1");
    assert_eq!(json["dst"], "203.0.113.5");
    assert_eq!(json["transport_proto"], "UDP");
    assert_eq!(json["sport"], 55555);
    assert_eq!(json["dport"], 53);
}
