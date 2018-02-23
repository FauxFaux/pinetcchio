use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::u16;

use csum;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Response {
    DestinationUnreachable,
    KnownInvalid,
}


pub fn v4(resp: Response, data: &[u8]) -> Vec<u8> {
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
    let checksum = csum::csum(&vec);
    BigEndian::write_u16(&mut vec[10..], checksum);

    assert_eq!(IP_LEN, vec.len());

    vec.extend(&match resp {
        Response::DestinationUnreachable => [3, 1],
        Response::KnownInvalid => unimplemented!(),
    });

    vec.extend(&[0, 0]); // checksum space
    vec.extend(&[0, 0, 0, 0]); // unused extra header space
    vec.extend(&data[..saved_data_len]);

    let checksum = csum::csum(&vec[IP_LEN..]);
    BigEndian::write_u16(&mut vec[IP_LEN + 2..], checksum);

    assert_eq!(total_len, vec.len());
    vec
}

pub fn v6(resp: Response, data: &[u8]) -> Vec<u8> {
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

    vec.push(::collect::IP_PROTOCOL_ICMP_V6);
    vec.push(0x40); // hop limit / TTL
    vec.extend(&data[24..40]); // source address
    vec.extend(&data[8..24]); // dest address

    assert_eq!(IP_LEN, vec.len());

    vec.extend(&match resp {
        Response::DestinationUnreachable => [1, 3],
        Response::KnownInvalid => unimplemented!(),
    });

    vec.extend(&[0, 0]); // checksum space
    vec.extend(&[0, 0, 0, 0]); // unused extra header space

    let checksum = csum::add(&vec[8..40]) + csum::add(&vec[4..6])
        + csum::add(&[0, 0, 0, ::collect::IP_PROTOCOL_ICMP_V6]);
    BigEndian::write_u16(&mut vec[IP_LEN + 2..], csum::finish(checksum));

    vec.extend(&data[..saved_data_len]);

    assert_eq!(total_len, vec.len());

    vec
}
