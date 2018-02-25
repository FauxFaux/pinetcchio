use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::u16;
use cast::u8;

use csum;

/// Abstracting over icmpv4/icmpv6, but not very well;
/// under the assumption that someone will eventually want an offset
/// into a non-standard packet, but they probably won't.
///
/// Mapping onto "parameter problem" is especially confusing:
/// icmpv4: (12, 0): any problem except length
/// icmpv4: (12, 1): problems with extended headers (uncommon)
/// icmpv4: (12, 2): problem with either length
///
/// icmpv6:  (4, 0): any problem except:
/// icmpv6:  (4, 1): next header unsupported
/// icmpv6:  (4, 2): unrecognised option
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Response {
    DestinationHostUnreachable,
    UnknownProtocol { offset: u32 },
    InvalidLength { offset: u32 },
    InvalidParameter { offset: u32 },
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

    let (codes, extra) = match resp {
        Response::DestinationHostUnreachable => ([3, 1], [0u8; 4]),
        Response::UnknownProtocol { offset } | Response::InvalidParameter { offset } => {
            ([12, 0], [u8(offset).unwrap(), 0, 0, 0])
        }
        Response::InvalidLength { offset } => ([12, 2], [u8(offset).unwrap(), 0, 0, 0]),
    };

    vec.extend(&codes);
    vec.extend(&[0, 0]); // checksum space
    vec.extend(&extra); // unused extra header space
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

    let (code, extra) = match resp {
        Response::DestinationHostUnreachable => ([1, 3], [0, 0, 0, 0]),
        Response::UnknownProtocol { offset } => ([4, 1], u32_array(offset)),
        Response::InvalidLength { offset } | Response::InvalidParameter { offset } => {
            ([4, 0], u32_array(offset))
        }
    };

    vec.extend(&code);
    vec.extend(&[0, 0]); // checksum space
    vec.extend(&extra); // unused extra header space

    vec.extend(&data[..saved_data_len]);

    let checksum = csum::add(&vec[8..40]) // source/dest address
        + csum::add(&vec[4..6]) // packet length?
        + csum::add(&[0, 0, 0, ::collect::IP_PROTOCOL_ICMP_V6]) // random zeros, and next header number
        + csum::add(&vec[IP_LEN..]); // code and zeros and data

    BigEndian::write_u16(&mut vec[IP_LEN + 2..], csum::finish(checksum));

    assert_eq!(total_len, vec.len());

    vec
}

fn u32_array(val: u32) -> [u8; 4] {
    let mut bytes = [0u8; 4];
    BigEndian::write_u32(&mut bytes, val);
    bytes
}

#[cfg(test)]
mod tests {
    /// trying to make it match a real network packet; too much entropy and
    ///  spec divergence; so I gave up
    #[ignore]
    #[test]
    fn un4() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let req = &[
            /* 0000 */ 0x45, 0x00, 0x00, 0x3c, 0x40, 0xc8, 0x40, 0x00, // E..<@.@.
            /* 0008 */ 0x40, 0x06, 0xad, 0xe7, 0xc0, 0xa8, 0x01, 0xeb, // @.......
            /* 0010 */ 0x5e, 0x17, 0x2b, 0x62, 0x8f, 0x26, 0x34, 0x3d, // ^.+b.&4=
            /* 0018 */ 0xd0, 0x56, 0x35, 0xe7, 0x00, 0x00, 0x00, 0x00, // .V5.....
            /* 0020 */ 0xa0, 0x02, 0x72, 0x10, 0x4c, 0x3b, 0x00, 0x00, // ..r.L;..
            /* 0028 */ 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, // ........
            /* 0030 */ 0x3d, 0x3c, 0x99, 0xdc, 0x00, 0x00, 0x00, 0x00, // =<......
            /* 0038 */ 0x01, 0x03, 0x03, 0x0a,                         // ....
        ];

        let resp = &[
            /* 0000 */ 0x45, 0x00, 0x00, 0x3c, 0x40, 0xc8, 0x40, 0x00, // E..<@.@.
            /* 0008 */ 0x40, 0x06, 0xad, 0xe7, 0xc0, 0xa8, 0x01, 0xeb, // @.......
            /* 0010 */ 0x5e, 0x17, 0x2b, 0x62, 0x8f, 0x26, 0x34, 0x3d, // ^.+b.&4=
            /* 0018 */ 0xd0, 0x56, 0x35, 0xe7, 0x00, 0x00, 0x00, 0x00, // .V5.....
            /* 0020 */ 0xa0, 0x02, 0x72, 0x10, 0x4c, 0x3b, 0x00, 0x00, // ..r.L;..
            /* 0028 */ 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, // ........
            /* 0030 */ 0x3d, 0x3c, 0x99, 0xdc, 0x00, 0x00, 0x00, 0x00, // =<......
            /* 0038 */ 0x01, 0x03, 0x03, 0x0au8,                       // ....
        ][..];

        assert_eq!(
            resp,
            super::v4(super::Response::DestinationHostUnreachable, req).as_slice()
        );
    }
}
