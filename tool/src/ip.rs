use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::u16;

use crate::csum;

pub fn v4_response<P>(src: &[u8], dest: &[u8], proto: u8, payload: P) -> Vec<u8>
where
    P: FnOnce(&mut Vec<u8>),
{
    const IP_LEN: usize = 20;

    let mut vec = Vec::with_capacity(IP_LEN);
    vec.extend(&[0x45, 0xc0]); // ip version, flags, ecn, ..
    vec.extend(&[0, 0]); // space for length

    // identification x2, flags, fragment, ttl, proto, checksum x2
    vec.extend(&[0, 0, 0, 0, 0x40, proto, 0, 0]);
    vec.extend(src);
    vec.extend(dest);

    assert_eq!(IP_LEN, vec.len());

    payload(&mut vec);

    // BORROW CHECKER
    let total_len = u16(vec.len()).unwrap();
    BigEndian::write_u16(&mut vec[2..], total_len);

    // BORROW CHECKER
    let checksum = csum::csum(&vec[..IP_LEN]);
    BigEndian::write_u16(&mut vec[10..], checksum);

    vec
}
