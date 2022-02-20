use pcap::{Capture, Device};
use std::convert::TryFrom;

#[derive(Clone)]
struct Ethernet2Frame<'a>(&'a [u8]);

#[derive(Clone, Debug)]
struct IpPacket<'a>(&'a [u8], String);

trait Addressable {
    fn source_address(&self) -> String;
    fn destination_address(&self) -> String;
}

trait HasPayload<'a> {
    fn payload(&self) -> &'a [u8];
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

impl<'a> Addressable for Ethernet2Frame<'a> {
    fn source_address(&self) -> String {
        print_hex(&self.0[..6])
    }

    fn destination_address(&self) -> String {
        print_hex(&self.0[6..12])
    }
}

impl<'a> HasPayload<'a> for Ethernet2Frame<'a> {
    fn payload(&self) -> &'a [u8] {
        &self.0[14..self.0.len() - 4]
    }
}

impl<'a> TryFrom<Ethernet2Frame<'a>> for IpPacket<'a> {
    type Error = &'static str;

    fn try_from(value: Ethernet2Frame<'a>) -> Result<Self, Self::Error> {
        let ethertype = &value.0[12..14];
        println!("{:?}", hex::encode(ethertype));

        if hex::encode(ethertype) == "0800" {
            Ok(IpPacket(value.payload(), String::from("IPv4")))
        } else if hex::encode(ethertype) == "86dd" {
            Ok(IpPacket(value.payload(), String::from("IPv6")))
        } else {
            Err("Not an IP protocol.")
        }
    }
}

impl<'a> Addressable for IpPacket<'a> {
    fn source_address(&self) -> String {
        if self.1 == "IPv4" {
            print_dot(&self.0[12..16])
        } else if self.1 == "IPv6" {
            print_hex(&self.0[8..24])
        } else {
            panic!();
        }
    }

    fn destination_address(&self) -> String {
        if self.1 == "IPv4" {
            print_dot(&self.0[16..20])
        } else if self.1 == "IPv6" {
            print_hex(&self.0[24..40])
        } else {
            panic!();
        }
    }
}

impl<'a> HasPayload<'a> for IpPacket<'a> {
    fn payload(&self) -> &'a [u8] {
        if self.1 == "IPv4" {
            &self.0[24..]
        } else if self.1 == "IPv6" {
            let mut offset = 40;
            let mut payload_length: usize = self.0[4] as usize;
            payload_length = payload_length << 8 + self.0[5];

            let extensions = [0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254];

            let mut it = self.0[4];

            while !extensions.contains(&(it as i32)) {
                it = self.0[offset];
                offset += 16;
                payload_length -= 16;
            }

            &self.0[offset..offset + payload_length]
        } else {
            panic!();
        }
    }
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

    loop {
        if let Ok(packet) = pcap.next() {
            let eth = Ethernet2Frame(packet.data);

            let mut root = serde_json::Map::new();

            let ethernet = serde_json::json!({
                "source": eth.source_address(),
                "destination": eth.destination_address(),
            });

            root.insert(String::from("ethernet"), ethernet);

            let ip = IpPacket::try_from(eth);
            
            if let Ok(ip2) = ip {
                let ip_packet = serde_json::json!({
                    "source": ip2.source_address(),
                    "destination": ip2.destination_address(),
                    "version": ip2.1
                });

                root.insert(String::from("ip"), ip_packet);

                
            }

            let mut s = String::from("");
            for b in packet.data {
                let c = char::from(b.clone());
                if c.is_alphanumeric() {
                    s.push(c);
                } else {
                    s.push_str(".");
                }
            }
            root.insert(String::from("data"), serde_json::Value::String(s));

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(root)).unwrap()
            )
        }
    }
}
