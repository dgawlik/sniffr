use pcap::{Capture, Device};
use std::convert::TryFrom;

#[derive(Clone)]
struct Ethernet2Frame<'a>(&'a [u8]);

#[derive(Clone)]
struct IpPacket<'a>(&'a [u8], String);

#[derive(Clone)]
struct TcpSegment<'a>(&'a [u8]);

#[derive(Clone)]
struct UdpPacket<'a>(&'a [u8]);


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
            &self.0[20..]
        } else if self.1 == "IPv6" {
            &self.0[40..]
        } else {
            panic!();
        }
    }
}

impl<'a> TryFrom<IpPacket<'a>> for UdpPacket<'a> {
    type Error = &'static str;

    fn try_from(value: IpPacket<'a>) -> Result<Self, Self::Error> {
        if value.1 == "IPv4" {
            if value.0[9] == 17 {
                Ok(UdpPacket(value.payload()))
            }
            else {
                Err("Not UDP protocol")
            }
        }
        else if value.1 == "IPv6" {

            if value.0[6] != 17 {
                Err("Not UDP protocol")
            }
            else {
                Ok(UdpPacket(value.payload()))
            }
        }
        else {
            panic!();
        }
    }
}

impl<'a> TryFrom<IpPacket<'a>> for TcpSegment<'a> {
    type Error = &'static str;

    fn try_from(value: IpPacket<'a>) -> Result<Self, Self::Error> {
        if value.1 == "IPv4" {
            if value.0[9] == 6 {
                Ok(TcpSegment(value.payload()))
            }
            else {
                Err("Not TCP protocol")
            }
        }
        else if value.1 == "IPv6" {
            if value.0[6] != 6 {
                Err("Not TCP protocol")
            }
            else {
                Ok(TcpSegment(value.payload()))
            }
        }
        else {
            panic!();
        }
    }
}


impl<'a> Addressable for UdpPacket<'a> {
    fn source_address(&self) -> String {
        let mut addr = (self.0[0] as u16) << 8;
        addr += self.0[1] as u16;
        format!("{}", addr)
    }

    fn destination_address(&self) -> String {
        let mut addr = (self.0[2] as u16) << 8;
        addr += self.0[3] as u16;
        format!("{}", addr)
    }
}


impl<'a> Addressable for TcpSegment<'a> {
    fn source_address(&self) -> String {
        let mut addr = (self.0[0] as u16) << 8;
        addr += self.0[1] as u16;
        format!("{}", addr)
    }

    fn destination_address(&self) -> String {
        let mut addr = (self.0[2] as u16) << 8;
        addr += self.0[3] as u16;
        format!("{}", addr)
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

                if let Ok(udp) = UdpPacket::try_from(ip2.clone()) {
                    let udp_packet = serde_json::json!({
                        "source": udp.source_address(),
                        "destination": udp.destination_address(),
                    });

                    root.insert(String::from("udp"), udp_packet);
                }

                if let Ok(tcp) = TcpSegment::try_from(ip2) {
                    let tcp_segment = serde_json::json!({
                        "source": tcp.source_address(),
                        "destination": tcp.destination_address(),
                    });

                    root.insert(String::from("tcp"), tcp_segment);
                }
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
