use etherparse::SlicedPacket;

/// Convert raw packet bytes (with timestamp fields) into a JSON object used by the CLI.
pub fn json_from_bytes(len: u32, ts_sec: i64, ts_usec: i64, data: &[u8]) -> serde_json::Value {
    match SlicedPacket::from_ethernet(data) {
        Ok(sliced) => {
            let tsf = (ts_sec as f64) + (ts_usec as f64) / 1_000_000.0;

            let mut net_proto = serde_json::Value::String("-".into());
            let mut src = serde_json::Value::String("-".into());
            let mut dst = serde_json::Value::String("-".into());
            if let Some(net) = &sliced.net {
                match net {
                    etherparse::InternetSlice::Ipv4(ipv4) => {
                        net_proto = serde_json::Value::String("IPv4".into());
                        let hdr = ipv4.header();
                        src = serde_json::Value::String(hdr.source_addr().to_string());
                        dst = serde_json::Value::String(hdr.destination_addr().to_string());
                    }
                    etherparse::InternetSlice::Ipv6(ipv6) => {
                        net_proto = serde_json::Value::String("IPv6".into());
                        let hdr = ipv6.header();
                        src = serde_json::Value::String(hdr.source_addr().to_string());
                        dst = serde_json::Value::String(hdr.destination_addr().to_string());
                    }
                }
            }

            let mut tproto = serde_json::Value::String("-".into());
            let mut sport = serde_json::Value::Null;
            let mut dport = serde_json::Value::Null;
            if let Some(transport) = &sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        tproto = serde_json::Value::String("TCP".into());
                        sport = serde_json::Value::Number(tcp.source_port().into());
                        dport = serde_json::Value::Number(tcp.destination_port().into());
                    }
                    etherparse::TransportSlice::Udp(udp) => {
                        tproto = serde_json::Value::String("UDP".into());
                        sport = serde_json::Value::Number(udp.source_port().into());
                        dport = serde_json::Value::Number(udp.destination_port().into());
                    }
                    _ => {}
                }
            }

            serde_json::json!({
                "timestamp": tsf,
                "len": len,
                "data_len": data.len(),
                "net_proto": net_proto,
                "src": src,
                "dst": dst,
                "transport_proto": tproto,
                "sport": sport,
                "dport": dport,
            })
        }
        Err(_) => serde_json::json!({
            "len": len,
            "data_len": data.len(),
        }),
    }
}
