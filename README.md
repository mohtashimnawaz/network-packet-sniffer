# Network Packet Sniffer (mini-Wireshark)

Simple CLI network packet sniffer written in Rust using `pcap` + `etherparse`.

## Features

- Live capture from network interface
- BPF filter support (`-f`)
- JSON output per-packet (`--json`)
- Optional colored/pretty output (`--pretty`)
- Control pretty output fields with `--pretty-format` (comma-separated list of fields: `ts,len,src,dst,sport,dport,proto`)
- Save captured packets to pcap (`-w out.pcap`)
- Protocol filtering (`--protocol tcp|udp|icmp`)

## Quick start

Build:

```bash
cargo build --release
```

Run (may require elevated privileges):

```bash
# capture on en0, print pretty output
sudo ./target/release/network-packet-sniffer --interface en0 --pretty --pretty-format ts,src,dst,proto

# capture 100 packets on en0 and save to file
sudo ./target/release/network-packet-sniffer -i en0 -c 100 -w out.pcap

# show JSON per packet
sudo ./target/release/network-packet-sniffer -i en0 --json

# use a BPF filter
sudo ./target/release/network-packet-sniffer -i en0 -f "tcp port 80"

# filter to TCP only
sudo ./target/release/network-packet-sniffer -i en0 --protocol tcp
```

### Permissions note

On macOS and many *nix systems you need permission to capture packets. You can:

- Run the program with `sudo` (recommended for quick tests)
- On macOS: give the binary entitlement to access the network, or run with `sudo`.

If you run into `Failed to open capture device` or `Failed to list devices` errors, try running with `sudo`.

## Testing

Project includes unit/integration tests that generate small packets programmatically, parse them and validate JSON output for expected fields.

## Contributing

PRs welcome — open an issue if you want features like protocol aggregation or per-interface selection UI.
