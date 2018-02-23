use cast::u16;
use cast::u64;

pub fn add(data: &[u8]) -> u64 {
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

pub fn finish(mut sum: u64) -> u16 {
    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while 0 != (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    u16(sum).unwrap() ^ 0xffff
}

pub fn csum(data: &[u8]) -> u16 {
    finish(add(data))
}
