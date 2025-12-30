use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use etherparse::SlicedPacket;
use pcap::{Capture, Device, Packet};
use std::path::PathBuf;

/// Simple network packet sniffer (mini-Wireshark)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to capture on (e.g. en0). If not provided, the first device is used.
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF filter string (e.g. "tcp and port 80")
    #[arg(short, long, default_value = "")]
    filter: String,

    /// Number of packets to capture (0 for infinite)
    #[arg(short, long, default_value_t = 0)]
    count: u64,

    /// Output in JSON per-packet
    #[arg(short, long)]
    json: bool,

    /// Pretty / colored structured output
    #[arg(long)]
    pretty: bool,

    /// Pretty format fields (comma-separated list: ts,len,src,dst,sport,dport,proto)
    #[arg(long)]
    pretty_format: Option<String>,

    /// Print hex dump of packet payloads
    #[arg(short, long)]
    hex: bool,

    /// Save captured packets to a pcap file
    #[arg(short = 'w', long)]
    write: Option<PathBuf>,

    /// Filter to a protocol (tcp|udp|icmp)
    #[arg(long)]
    protocol: Option<String>,
}

fn ts_to_secs(ts_sec: i64, ts_usec: i64) -> f64 {
    ts_sec as f64 + (ts_usec as f64) / 1_000_000.0
}

// NOTE: JSON helper lives in `src/lib.rs` as `json_from_bytes` for reuse by tests and CLI.



fn print_packet(packet: &Packet, args: &Args) {
    match SlicedPacket::from_ethernet(packet.data) {
        Ok(sliced) => {
            // protocol filter
            if let Some(proto) = &args.protocol {
                let proto_l = proto.to_ascii_lowercase();
                let mut keep = false;
                match &sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(_)) if proto_l == "tcp" => keep = true,
                    Some(etherparse::TransportSlice::Udp(_)) if proto_l == "udp" => keep = true,
                    _ => {}
                }
                if !keep {
                    return;
                }
            }

            let ts = packet.header.ts;
            let tsf = ts_to_secs(ts.tv_sec.into(), ts.tv_usec.into());

            // Network layer
            let mut net_proto = "-".to_string();
            let mut src = "-".to_string();
            let mut dst = "-".to_string();
            if let Some(net) = &sliced.net {
                match net {
                    etherparse::InternetSlice::Ipv4(ipv4) => {
                        net_proto = "IPv4".into();
                        let hdr = ipv4.header();
                        src = hdr.source_addr().to_string();
                        dst = hdr.destination_addr().to_string();
                    }
                    etherparse::InternetSlice::Ipv6(ipv6) => {
                        net_proto = "IPv6".into();
                        let hdr = ipv6.header();
                        src = hdr.source_addr().to_string();
                        dst = hdr.destination_addr().to_string();
                    }
                }
            }

            // Transport layer
            let mut tproto = "-".to_string();
            let mut sport: Option<u16> = None;
            let mut dport: Option<u16> = None;
            if let Some(transport) = &sliced.transport {
                match transport {
                    etherparse::TransportSlice::Tcp(tcp) => {
                        tproto = "TCP".into();
                        sport = Some(tcp.source_port());
                        dport = Some(tcp.destination_port());
                    }
                    etherparse::TransportSlice::Udp(udp) => {
                        tproto = "UDP".into();
                        sport = Some(udp.source_port());
                        dport = Some(udp.destination_port());
                    }
                }
            }

            // Pretty output
            if args.pretty {
                use colored::Colorize;

                // Determine fields to render
                let fields: Vec<&str> = args
                    .pretty_format
                    .as_ref()
                    .map(|s| s.split(',').map(|p| p.trim()).collect())
                    .unwrap_or_else(|| vec!["ts", "len", "src", "dst", "proto"]);

                let mut parts: Vec<String> = Vec::new();
                for &f in &fields {
                    match f {
                        "ts" => parts.push(format!("{:.6}", tsf).cyan().to_string()),
                        "len" => parts.push(format!("len={}", packet.header.len).cyan().to_string()),
                        "src" => parts.push(src.as_str().green().to_string()),
                        "dst" => parts.push(dst.as_str().red().to_string()),
                        "sport" => parts.push(sport.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string())),
                        "dport" => parts.push(dport.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string())),
                        "proto" => parts.push(tproto.as_str().yellow().to_string()),
                        _ => {}
                    }
                }

                println!("{}", parts.join(" "));
            } else {
                let sport_str = sport.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
                let dport_str = dport.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());

                let line = format!(
                    "{:.6} len={} {} {}:{} -> {}:{} {}",
                    tsf, packet.header.len, net_proto, src, sport_str, dst, dport_str, tproto
                );
                println!("{}", line);
            }

            if args.hex {
                // Print hex dump of the packet data
                for (i, chunk) in packet.data.chunks(16).enumerate() {
                    print!("{:04x}: ", i * 16);
                    for b in chunk {
                        print!("{:02x} ", b);
                    }
                    println!();
                }
            }
        }
        Err(err) => {
            eprintln!("Failed to parse packet: {} -- raw len={}", err, packet.header.len);
            if args.hex {
                for (i, chunk) in packet.data.chunks(16).enumerate() {
                    print!("{:04x}: ", i * 16);
                    for b in chunk {
                        print!("{:02x} ", b);
                    }
                    println!();
                }
            }
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let device_name = if let Some(ref ifname) = args.interface {
        ifname.clone()
    } else {
        // pick the first device
        let devs = Device::list().context("Failed to list devices; try running with sudo")?;
        let first = devs
            .into_iter()
            .next()
            .context("No devices available on this host")?
            .name;
        first
    };

    println!("Capturing on interface: {}", device_name);

    let mut cap = Capture::from_device(device_name.as_str())?
        .promisc(true)
        .snaplen(65535)
        .open()
        .context("Failed to open capture device; try running with sudo or granting pcap permissions")?;

    if !args.filter.is_empty() {
        cap.filter(&args.filter, true)
            .context("Failed to set BPF filter")?;
        println!("Using BPF filter: {}", args.filter);
    }

    // Optional: open a savefile
    let mut writer = match args.write.as_ref() {
        Some(path) => Some(cap.savefile(path).context("Failed to create pcap savefile")?),
        None => None,
    };

    let mut seen: u64 = 0;
    loop {
        let packet = match cap.next_packet() {
            Ok(pkt) => pkt,
            Err(pcap::Error::NoMorePackets) => {
                // In live capture this should not happen; continue
                continue;
            }
            Err(e) => {
                eprintln!("Error while capturing packet: {}", e);
                break;
            }
        };

        if let Some(ref mut w) = writer {
            // write copy to pcap savefile (Savefile::write takes a slice)
            w.write(&packet);
            if let Err(e) = w.flush() {
                eprintln!("Failed to flush savefile: {}", e);
            }
        }

        if args.json {
            // JSON output with parsed fields when possible
            // Apply protocol filter when requested
            if let Some(proto) = &args.protocol {
                if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data) {
                    let proto_l = proto.to_ascii_lowercase();
                    let matches = match sliced.transport {
                        Some(etherparse::TransportSlice::Tcp(_)) => proto_l == "tcp",
                        Some(etherparse::TransportSlice::Udp(_)) => proto_l == "udp",
                        _ => false,
                    };
                    if !matches {
                        continue;
                    }
                }
            }

            let ts = packet.header.ts;
            let output = network_packet_sniffer::json_from_bytes(packet.header.len, ts.tv_sec.into(), ts.tv_usec.into(), packet.data);
            println!("{}", serde_json::to_string(&output)?);
        } else {
            print_packet(&packet, &args);
        }

        seen += 1;
        if args.count != 0 && seen >= args.count {
            println!("Captured {} packets, exiting", seen);
            break;
        }
    }

    Ok(())
}
