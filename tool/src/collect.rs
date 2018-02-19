use std::fmt;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::*;
use fdns_parse::parse as fdns;
use mio;

use errors::*;

const IP_FLAG_DONT_FRAGMENT: u8 = 1 << 6;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

#[derive(Copy, Clone, Debug)]
enum Protocol {
    Tcp,
    Udp,
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

    loop {
        poll.poll(&mut events, None)?;

        for ev in events.iter() {
            match ev.token() {
                TUN_TOKEN => {
                    assert_eq!(mio::Ready::readable(), ev.readiness());
                    let mut buf = [0u8; 4 * 1024];
                    let read = tun_file.read(&mut buf)?;
                    let buf = &buf[..read];
                    println!("{:?}", handle(buf));
                }
                _ => unimplemented!("unexpected token"),
            }
        }
    }

    Ok(())
}

fn header_length(buf: &[u8]) -> u16 {
    u16::from(buf[0] & 0x0f) * 32 / 8
}

fn handle(buf: &[u8]) -> Result<String> {
    match buf[0] & 0xf0 {
        0x40 => handle_v4(buf),
        0x60 => handle_v6(buf),
        version => bail!("unsupported ip version: {:x}", version),
    }
}

fn handle_v4(buf: &[u8]) -> Result<String> {
    let ip_header_length = header_length(buf);
    ensure!(20 == ip_header_length, "unsupported header length");
    ensure!(buf.len() >= usize(ip_header_length), "truncated header");

    // buf[1]: DSCP / ECN: unsupported

    let ip_total_length = read_u16(&buf[2..]);
    let identification = read_u16(&buf[4..]);

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

    let buf = &buf[ip_header_length as usize..];

    Ok(format!(
        "ipv4 {:?} -> {:?} {:?} {:?}",
        src,
        dest,
        protocol,
        handle_protocol(protocol, buf),
    ))
}

fn handle_v6(buf: &[u8]) -> Result<String> {
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
        58 => bail!("unsupported ipv6 nonsense: no data"),
        next_header => bail!("unsupported next header number: {}", next_header),
    };

    // buf[7]: hop limit (ignored)

    let src = read_v6(&buf[8..]);
    let dest = read_v6(&buf[24..]);

    let buf = &buf[V6_HEADER_LEN..];

    Ok(format!(
        "ipv6 {:?} -> {:?} {:?} remainder: {:?}",
        src,
        dest,
        protocol,
        handle_protocol(protocol, buf),
    ))
}

fn handle_protocol(protocol: Protocol, buf: &[u8]) -> Result<String> {
    match protocol {
        Protocol::Udp => handle_udp(buf),
        Protocol::Tcp => handle_tcp(buf),
    }
}

fn handle_udp(buf: &[u8]) -> Result<String> {
    let src_port = read_u16(buf);
    let dst_port = read_u16(&buf[2..]);

    // TODO: length, checksum

    let buf = &buf[8..];

    if 53 == dst_port {
        return Ok(format!("src: {}, dns: {:?}", src_port, fdns::parse(buf)));
    }

    Ok(format!(
        "{} -> {}, remaining: {}",
        src_port,
        dst_port,
        ::hex::encode(buf)
    ))
}

fn handle_tcp(buf: &[u8]) -> Result<String> {
    let src_port = read_u16(buf);
    let dst_port = read_u16(&buf[2..]);

    Ok(format!(
        "{} -> {}, remaining: {}",
        src_port,
        dst_port,
        ::hex::encode(&buf[20..])
    ))
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
