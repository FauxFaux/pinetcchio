use std::fs;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::time::SystemTime;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::*;
use fdns_parse::parse as fdns;
use mio;
use pcap_file;
use pcap_file::PcapWriter;

use dns;
use errors::*;

const IP_FLAG_DONT_FRAGMENT: u8 = 1 << 6;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ICMP_V4: u8 = 1;
const IP_PROTOCOL_ICMP_V6: u8 = 58;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum IpVersion {
    Four,
    Six,
}

#[derive(Copy, Clone, Debug)]
enum Protocol {
    Tcp,
    Udp,
    IcmpV4,
    IcmpV6,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum IcmpResponse {
    DestinationUnreachable,
    KnownInvalid,
}

#[derive(Clone, Debug)]
enum Immediate {
    Icmp(IcmpResponse),
    Drop(String),
    Debug(String),
}

pub fn watch(tun: RawFd) -> Result<()> {
    assert!(tun > 0);

    let poll = mio::Poll::new()?;

    const TUN_TOKEN: mio::Token = mio::Token(0);
    let tun_struct = mio::unix::EventedFd(&tun);
    poll.register(
        &tun_struct,
        TUN_TOKEN,
        mio::Ready::readable(),
        mio::PollOpt::level(),
    )?;

    let mut tun_file = unsafe { fs::File::from_raw_fd(tun) };

    let mut events = mio::Events::with_capacity(1024);
    let mut internal_resolver = dns::InternalResolver::default();
    let mut write = Vec::new();
    let mut pcap = PcapWriter::with_header(
        pcap_file::PcapHeader::with_datalink(pcap_file::DataLink::RAW),
        fs::File::create("all.pcap")?,
    )?;
    let start = SystemTime::now();

    loop {
        poll.poll(&mut events, None)?;

        for ev in events.iter() {
            if ev.token() == TUN_TOKEN {
                if ev.readiness().contains(mio::Ready::readable()) {
                    let mut buf = [0u8; 4 * 1024];
                    let read = tun_file.read(&mut buf)?;
                    let buf = &buf[..read];
                    write_pcap(&mut pcap, start, buf)?;
                    if let Some(pkt) = handle(buf)? {
                        write.push(pkt);
                        poll.reregister(
                            &tun_struct,
                            TUN_TOKEN,
                            mio::Ready::readable() | mio::Ready::writable(),
                            mio::PollOpt::level(),
                        )?;
                    }
                }

                if ev.readiness().contains(mio::Ready::writable()) {
                    match write.pop() {
                        Some(ref val) => {
                            write_pcap(&mut pcap, start, val)?;
                            tun_file.write_all(val)?;
                        }
                        None => poll.reregister(
                            &tun_struct,
                            TUN_TOKEN,
                            mio::Ready::readable(),
                            mio::PollOpt::level(),
                        )?,
                    }
                }
            } else {
                unimplemented!("unexpected token")
            }
        }
    }
}

fn write_pcap<W: Write>(pcap: &mut PcapWriter<W>, start: SystemTime, buf: &[u8]) -> Result<()> {
    let duration = SystemTime::now().duration_since(start)?;
    pcap.write(u32(duration.as_secs())?, duration.subsec_micros(), buf)?;
    Ok(())
}

fn icmp(resp: IcmpResponse, data: &[u8]) -> Vec<u8> {
    const IP_LEN: usize = 20;
    const ICMP_LEN: usize = 8;
    const MTU: usize = 576;
    const PREFIX_LEN: usize = IP_LEN + ICMP_LEN;
    const MAX_DATA: usize = MTU - PREFIX_LEN;
    let saved_data_len = MAX_DATA.min(data.len());
    let total_len = PREFIX_LEN + saved_data_len;

    let mut vec = Vec::with_capacity(total_len);
    vec.extend(&[0x45, 0xc0]); // ip version, flags, ecn, ..
    vec.extend(&[0, 0]); // space for length
    BigEndian::write_u16(&mut vec[2..], u16(total_len).unwrap());

    // identification x2, flags, fragment, ttl, proto, checksum x2
    vec.extend(&[0, 0, 0, 0, 0x40, 1, 0, 0]);
    let old_to_address = &data[16..20];
    vec.extend(old_to_address);
    vec.extend(&[192, 168, 33, 2]);

    // BORROW CHECKER
    let checksum = internet_checksum(&vec);
    BigEndian::write_u16(&mut vec[10..], checksum);

    assert_eq!(IP_LEN, vec.len());

    vec.extend(&match resp {
        IcmpResponse::DestinationUnreachable => [3, 1],
        IcmpResponse::KnownInvalid => unimplemented!(),
    });

    vec.extend(&[0, 0]); // checksum space
    vec.extend(&[0, 0, 0, 0]); // unused extra header space
    vec.extend(&data[..saved_data_len]);

    let checksum = internet_checksum(&vec[IP_LEN..]);
    BigEndian::write_u16(&mut vec[IP_LEN + 2..], checksum);

    assert_eq!(total_len, vec.len());
    vec
}

fn icmpv6(resp: IcmpResponse, data: &[u8]) -> Vec<u8> {
    const IP_LEN: usize = 40;
    const ICMP_LEN: usize = 8;
    const MTU: usize = 1280;
    const PREFIX_LEN: usize = IP_LEN + ICMP_LEN;
    const MAX_DATA: usize = MTU - PREFIX_LEN;
    let saved_data_len = MAX_DATA.min(data.len());
    let total_len = PREFIX_LEN + saved_data_len;

    let mut vec = Vec::with_capacity(total_len);
    vec.extend(&[0x60, 0, 0, 0]); // version, traffic class, flow label
    vec.extend(&[0, 0]); // space for payload length
    BigEndian::write_u16(&mut vec[4..], u16(ICMP_LEN + saved_data_len).unwrap());

    vec.push(IP_PROTOCOL_ICMP_V6);
    vec.push(0x40); // hop limit / TTL
    vec.extend(&data[24..40]); // source address
    vec.extend(&data[8..24]); // dest address

    assert_eq!(IP_LEN, vec.len());

    vec.extend(&match resp {
        IcmpResponse::DestinationUnreachable => [1, 3],
        IcmpResponse::KnownInvalid => unimplemented!(),
    });

    vec.extend(&[0, 0]); // checksum space
    vec.extend(&[0, 0, 0, 0]); // unused extra header space

    let checksum = internet_add(&vec[8..40]) + internet_add(&vec[4..6])
        + internet_add(&[0, 0, 0, IP_PROTOCOL_ICMP_V6]);
    BigEndian::write_u16(&mut vec[IP_LEN + 2..], internet_finish(checksum));

    vec.extend(&data[..saved_data_len]);

    assert_eq!(total_len, vec.len());

    vec
}

fn internet_add(data: &[u8]) -> u64 {
    use itertools::Itertools;
    let mut sum = 0;
    for (&a, &b) in data.iter().tuples() {
        sum += u64(a) * 0x100;
        sum += u64(b);
    }

    if data.len() % 2 == 1 {
        sum += u64(data[data.len() - 1]) * 0x100;
    }

    sum
}

fn internet_finish(mut sum: u64) -> u16 {
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while 0 != (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    u16(sum).unwrap() ^ 0xffff
}

fn internet_checksum(data: &[u8]) -> u16 {
    internet_finish(internet_add(data))
}

fn header_length(buf: &[u8]) -> u16 {
    u16::from(buf[0] & 0x0f) * 32 / 8
}

fn ip_version(first_byte: u8) -> Result<IpVersion> {
    Ok(match first_byte & 0xf0 {
        0x40 => IpVersion::Four,
        0x60 => IpVersion::Six,
        version => bail!("unsupported ip version: {:x}", version),
    })
}

fn handle(buf: &[u8]) -> Result<Option<Box<[u8]>>> {
    match ip_version(buf[0])? {
        IpVersion::Four => handle_v4(buf),
        IpVersion::Six => handle_v6(buf),
    }
}

fn handle_v4(buf: &[u8]) -> Result<Option<Box<[u8]>>> {
    let ip_header_length = header_length(buf);
    ensure!(20 == ip_header_length, "unsupported header length");
    ensure!(buf.len() >= usize(ip_header_length), "truncated header");

    // buf[1]: DSCP / ECN: unsupported

    let ip_total_length = read_u16(&buf[2..]);
    ensure!(
        usize(ip_total_length) == buf.len(),
        "ip total length violation, actual: {}, stated: {}",
        buf.len(),
        ip_total_length
    );

    // buf[4..5]: identification (ignored)

    ensure!(
        IP_FLAG_DONT_FRAGMENT == buf[6] & IP_FLAG_DONT_FRAGMENT,
        "don't fragment"
    );
    // buf[6..7]: fragmentation (ignored)
    // buf[8]: ttl (ignored)

    let protocol = match buf[9] {
        IP_PROTOCOL_TCP => Protocol::Tcp,
        IP_PROTOCOL_UDP => Protocol::Udp,
        protocol => bail!("unsupported protocol number: {}", protocol),
    };

    let src = read_v4(&buf[12..]);
    let dest = read_v4(&buf[16..]);

    ensure!(buf.len() > 40, "too short for assumed tcp");

    println!("ipv4 {:?} -> {:?} {:?}", src, dest, protocol,);

    Ok(
        match handle_protocol(protocol, &buf[ip_header_length as usize..]) {
            Ok(Immediate::Icmp(resp)) => Some(icmp(resp, buf).into_boxed_slice()),
            Ok(Immediate::Debug(msg)) => {
                println!("replying denied: {}", msg);
                Some(icmp(IcmpResponse::DestinationUnreachable, buf).into_boxed_slice())
            }
            other => {
                println!("dropping: {:?}", other);
                None
            }
        },
    )
}

fn handle_v6(buf: &[u8]) -> Result<Option<Box<[u8]>>> {
    const V6_HEADER_LEN: usize = 40;

    ensure!(buf.len() >= V6_HEADER_LEN, "header is truncated");

    // buf[0..1]: traffic class (ignored)
    // buf[1..3]: flow label (ignored)
    ensure!(
        read_u16(&buf[4..]) as usize == buf.len() - V6_HEADER_LEN,
        "packet truncated"
    );

    let protocol = match buf[6] {
        IP_PROTOCOL_TCP => Protocol::Tcp,
        IP_PROTOCOL_UDP => Protocol::Udp,
        IP_PROTOCOL_ICMP_V6 => Protocol::IcmpV6,
        next_header => bail!("unsupported next header number: {}", next_header),
    };

    // buf[7]: hop limit (ignored)

    let src = read_v6(&buf[8..]);
    let dest = read_v6(&buf[24..]);

    println!("ipv6 {:?} -> {:?} {:?}", src, dest, protocol,);

    Ok(match handle_protocol(protocol, &buf[V6_HEADER_LEN..]) {
        Ok(Immediate::Icmp(resp)) => Some(icmpv6(resp, buf).into_boxed_slice()),
        Ok(Immediate::Debug(msg)) => {
            println!("replying denied: {}", msg);
            Some(icmpv6(IcmpResponse::DestinationUnreachable, buf).into_boxed_slice())
        }
        other => {
            println!("dropping: {:?}", other);
            None
        }
    })
}

fn handle_protocol(protocol: Protocol, buf: &[u8]) -> Result<Immediate> {
    match protocol {
        Protocol::Udp => handle_udp(buf),
        Protocol::Tcp => handle_tcp(buf),
        Protocol::IcmpV4 => handle_icmp(IpVersion::Four, buf),
        Protocol::IcmpV6 => handle_icmp(IpVersion::Six, buf),
    }
}

fn handle_udp(buf: &[u8]) -> Result<Immediate> {
    let src_port = read_u16(buf);
    let dst_port = read_u16(&buf[2..]);

    // TODO: length, checksum

    let buf = &buf[8..];

    if 53 == dst_port {
        return Ok(Immediate::Debug(format!(
            "src: {}, dns: {:?}",
            src_port,
            fdns::parse(buf)
        )));
    }

    Ok(Immediate::Debug(format!(
        "{} -> {}, remaining: {}",
        src_port,
        dst_port,
        ::hex::encode(buf)
    )))
}

fn handle_tcp(buf: &[u8]) -> Result<Immediate> {
    let src_port = read_u16(buf);
    let dst_port = read_u16(&buf[2..]);

    Ok(Immediate::Debug(format!(
        "{} -> {}, remaining: {}",
        src_port,
        dst_port,
        ::hex::encode(&buf[20..])
    )))
}

fn handle_icmp(version: IpVersion, buf: &[u8]) -> Result<Immediate> {
    let typ = buf[0];
    let code = buf[1];

    Ok(Immediate::Drop(format!(
        "({}, {}), remaining: {}",
        typ,
        code,
        ::hex::encode(&buf[4..])
    )))
}

fn read_u16(buf: &[u8]) -> u16 {
    BigEndian::read_u16(buf)
}

fn read_v4(buf: &[u8]) -> Ipv4Addr {
    let mut four = [0u8; 4];
    four.copy_from_slice(&buf[..4]);
    four.into()
}

fn read_v6(buf: &[u8]) -> Ipv6Addr {
    let mut sixteen = [0u8; 16];
    sixteen.copy_from_slice(&buf[..16]);
    sixteen.into()
}
