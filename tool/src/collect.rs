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
use icmp;

const IP_FLAG_DONT_FRAGMENT: u8 = 1 << 6;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ICMP_V4: u8 = 1;
pub const IP_PROTOCOL_ICMP_V6: u8 = 58;

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

#[derive(Clone, Debug)]
enum Immediate {
    Icmp(icmp::Response),
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
        protocol => {
            warn!("unsupported protocol number (untested icmp): {}", protocol);
            return Ok(Some(
                icmp::v6(icmp::Response::UnknownProtocol { offset: 9 }, buf).into_boxed_slice(),
            ));
        }
    };

    let src = read_v4(&buf[12..]);
    let dest = read_v4(&buf[16..]);

    ensure!(buf.len() > 40, "too short for assumed tcp");

    info!("ipv4 {:?} -> {:?} {:?}", src, dest, protocol,);

    Ok(
        match handle_protocol(protocol, &buf[ip_header_length as usize..]) {
            Ok(Immediate::Icmp(resp)) => Some(icmp::v4(resp, buf).into_boxed_slice()),
            Ok(Immediate::Debug(msg)) => {
                info!("replying denied: {}", msg);
                Some(icmp::v4(icmp::Response::DestinationUnreachable, buf).into_boxed_slice())
            }
            other => {
                info!("dropping: {:?}", other);
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
        next_header => {
            warn!("unsupported next header (untested icmp): {}", next_header);
            return Ok(Some(
                icmp::v6(icmp::Response::UnknownProtocol { offset: 6 }, buf).into_boxed_slice(),
            ));
        }
    };

    // buf[7]: hop limit (ignored)

    let src = read_v6(&buf[8..]);
    let dest = read_v6(&buf[24..]);

    info!("ipv6 {:?} -> {:?} {:?}", src, dest, protocol,);

    Ok(match handle_protocol(protocol, &buf[V6_HEADER_LEN..]) {
        Ok(Immediate::Icmp(resp)) => Some(icmp::v6(resp, buf).into_boxed_slice()),
        Ok(Immediate::Debug(msg)) => {
            info!("replying denied: {}", msg);
            Some(icmp::v6(icmp::Response::DestinationUnreachable, buf).into_boxed_slice())
        }
        other => {
            info!("dropping: {:?}", other);
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
