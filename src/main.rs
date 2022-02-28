use clap::Parser;
use jsonpath_rust::JsonPathFinder;
use pcap::{Capture, Device};

#[derive(Parser, Debug)]
#[clap(
    author = "Dominik Gawlik",
    version = "0",
    about = "Sniffr",
    long_about = "Simple sniffer in Rust"
)]
struct Args {
    #[clap(short='q', long="jpath-query", default_value_t=String::from("$"))]
    query: String,
}

enum Record<'a> {
    Ethernet2Frame(&'a [u8]),
    Ip4Packet(&'a [u8]),
    Ip6Packet(&'a [u8]),
    TcpSegment(&'a [u8]),
    UdpPacket(&'a [u8]),
}

fn print_dot(data: &[u8]) -> String {
    data.to_vec()
        .iter()
        .map(|x| format!("{}", x))
        .reduce(|a, b| format!("{}.{}", a, b))
        .unwrap()
}

fn print_hex(data: &[u8]) -> String {
    data.to_vec()
        .iter()
        .map(|x| hex::encode([*x]))
        .reduce(|a, b| format!("{}:{}", a, b))
        .unwrap()
}

fn source_address(rec: &Record) -> String {
    match rec {
        Record::Ethernet2Frame(b) => print_hex(&b[..6]),
        Record::Ip4Packet(b) => print_dot(&b[12..16]),
        Record::Ip6Packet(b) => print_hex(&b[8..24]),
        Record::TcpSegment(b) => {
            let mut addr = (b[0] as u16) << 8;
            addr += b[1] as u16;
            format!("{}", addr)
        }
        Record::UdpPacket(b) => {
            let mut addr = (b[0] as u16) << 8;
            addr += b[1] as u16;
            format!("{}", addr)
        }
    }
}

fn destination_address(rec: &Record) -> String {
    match rec {
        Record::Ethernet2Frame(b) => print_hex(&b[6..12]),
        Record::Ip4Packet(b) => print_dot(&b[16..20]),
        Record::Ip6Packet(b) => print_hex(&b[24..40]),
        Record::UdpPacket(b) => {
            let mut addr = (b[2] as u16) << 8;
            addr += b[3] as u16;
            format!("{}", addr)
        }
        Record::TcpSegment(b) => {
            let mut addr = (b[2] as u16) << 8;
            addr += b[3] as u16;
            format!("{}", addr)
        }
    }
}

fn payload<'a>(rec: &'a Record) -> &'a [u8] {
    match rec {
        Record::Ethernet2Frame(b) => &b[14..b.len() - 4],
        Record::Ip4Packet(b) => &b[20..],
        Record::Ip6Packet(b) => &b[40..],
        Record::UdpPacket(b) => &b[8..],
        Record::TcpSegment(b) => {
            let hdr_len = (b[12] >> 4) as usize;
            &b[hdr_len..]
        }
    }
}

fn name(rec: &Record) -> String {
    match rec {
        Record::Ethernet2Frame(_b) => String::from("Ethernet2"),
        Record::Ip4Packet(_b) => String::from("IPv4"),
        Record::Ip6Packet(_b) => String::from("IPv6"),
        Record::UdpPacket(_b) => String::from("UDP"),
        Record::TcpSegment(_b) => String::from("TCP"),
    }
}

fn unwrap<'a>(rec: &'a Record) -> &'a [u8] {
    match rec {
        Record::Ethernet2Frame(b) => b,
        Record::Ip4Packet(b) => b,
        Record::Ip6Packet(b) => b,
        Record::UdpPacket(b) => b,
        Record::TcpSegment(b) => b,
    }
}

fn decapsulate<'a>(rec: &'a Record) -> Option<Record<'a>> {
    match rec {
        eth @ Record::Ethernet2Frame(b) => {
            let ethertype = &b[12..14];

            if hex::encode(ethertype) == "0800" {
                Some(Record::Ip4Packet(payload(eth)))
            } else if hex::encode(ethertype) == "86dd" {
                Some(Record::Ip6Packet(payload(eth)))
            } else {
                None
            }
        }
        ip4 @ Record::Ip4Packet(b) => {
            if b[9] == 17 {
                Some(Record::UdpPacket(payload(ip4)))
            } else if b[9] == 6 {
                Some(Record::TcpSegment(payload(ip4)))
            } else {
                None
            }
        }
        ip6 @ Record::Ip6Packet(b) => {
            if b[6] == 17 {
                Some(Record::UdpPacket(payload(ip6)))
            } else if b[6] == 6 {
                Some(Record::TcpSegment(payload(ip6)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn data_print_utf8(data: &[u8]) -> String {
    let mut s = String::from("");
    for b in data {
        let c = char::from(b.clone());
        if c.is_alphanumeric() {
            s.push(c);
        } else {
            s.push_str(".");
        }
    }
    s
}

fn data_print_hex(data: &[u8]) -> String {
    hex::encode(data)
}

fn main() {
    let device = Device::lookup().unwrap();

    let mut pcap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .snaplen(5000)
        .open()
        .unwrap();

    let args = Args::parse();

    loop {
        if let Ok(packet) = pcap.next() {
            let eth = Record::Ethernet2Frame(packet.data);

            let mut root = serde_json::Map::new();

            let ethernet = serde_json::json!({
                "source": source_address(&eth),
                "destination": destination_address(&eth),
                "data": data_print_utf8(payload(&eth)),
                "data_hex": data_print_hex(payload(&eth))
            });

            root.insert(name(&eth), ethernet);

            if let Some(ip) = decapsulate(&eth) {
                let ip_packet = serde_json::json!({
                    "source": source_address(&ip),
                    "destination": destination_address(&ip),
                    "data": data_print_utf8(payload(&ip)),
                    "data_hex": data_print_hex(payload(&ip))
                });

                root.insert(name(&ip), ip_packet);

                if let Some(l4) = decapsulate(&ip) {
                    let l4_packet = serde_json::json!({
                        "source": source_address(&l4),
                        "destination": destination_address(&l4),
                        "data": data_print_utf8(payload(&l4)),
                        "data_hex": data_print_hex(payload(&l4))
                    });

                    root.insert(name(&l4), l4_packet);
                }
            }

            let obj = serde_json::Value::Object(root);

            match JsonPathFinder::from_str(obj.to_string().as_str(), &args.query.as_str()) {
                Ok(finder) => {
                    if finder.find_slice().len() > 0  {
                        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
                    }
                }
                Err(e) => panic!("error while parsing json or jsonpath: {}", e)
            }
        }
    }
}
