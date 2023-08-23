use std::mem::size_of;

use crate::{paranoid_hash::Hasher, Error, Result};

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MD5 {
    state: [u32; 4],
    count: u64,
    is_done: bool,
    digest: [u8; Self::DIGEST_SIZE],
}

impl Hasher for MD5 {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, Self::BLOCK_SIZE, u32, u64, "wrapping", "le");
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, Self::BLOCK_SIZE, u32, u64, "wrapping", "le");
    }

    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest)
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

impl MD5 {
    pub const BLOCK_SIZE: usize = 64;
    pub const DIGEST_SIZE: usize = 16;

    const U32_BLOCK_SIZE: usize = Self::BLOCK_SIZE / size_of::<u32>();

    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            is_done: false,
            digest: [0; Self::DIGEST_SIZE],
        }
    }

    #[inline]
    fn update_block(&mut self, block: &[u32; Self::U32_BLOCK_SIZE]) {
        let [mut a, mut b, mut c, mut d] = self.state;

        a = round_1(a, b, c, d, block[0], S11, 0xd76aa478);
        d = round_1(d, a, b, c, block[1], S12, 0xe8c7b756);
        c = round_1(c, d, a, b, block[2], S13, 0x242070db);
        b = round_1(b, c, d, a, block[3], S14, 0xc1bdceee);
        a = round_1(a, b, c, d, block[4], S11, 0xf57c0faf);
        d = round_1(d, a, b, c, block[5], S12, 0x4787c62a);
        c = round_1(c, d, a, b, block[6], S13, 0xa8304613);
        b = round_1(b, c, d, a, block[7], S14, 0xfd469501);
        a = round_1(a, b, c, d, block[8], S11, 0x698098d8);
        d = round_1(d, a, b, c, block[9], S12, 0x8b44f7af);
        c = round_1(c, d, a, b, block[10], S13, 0xffff5bb1);
        b = round_1(b, c, d, a, block[11], S14, 0x895cd7be);
        a = round_1(a, b, c, d, block[12], S11, 0x6b901122);
        d = round_1(d, a, b, c, block[13], S12, 0xfd987193);
        c = round_1(c, d, a, b, block[14], S13, 0xa679438e);
        b = round_1(b, c, d, a, block[15], S14, 0x49b40821);

        a = round_2(a, b, c, d, block[1], S21, 0xf61e2562);
        d = round_2(d, a, b, c, block[6], S22, 0xc040b340);
        c = round_2(c, d, a, b, block[11], S23, 0x265e5a51);
        b = round_2(b, c, d, a, block[0], S24, 0xe9b6c7aa);
        a = round_2(a, b, c, d, block[5], S21, 0xd62f105d);
        d = round_2(d, a, b, c, block[10], S22, 0x2441453);
        c = round_2(c, d, a, b, block[15], S23, 0xd8a1e681);
        b = round_2(b, c, d, a, block[4], S24, 0xe7d3fbc8);
        a = round_2(a, b, c, d, block[9], S21, 0x21e1cde6);
        d = round_2(d, a, b, c, block[14], S22, 0xc33707d6);
        c = round_2(c, d, a, b, block[3], S23, 0xf4d50d87);
        b = round_2(b, c, d, a, block[8], S24, 0x455a14ed);
        a = round_2(a, b, c, d, block[13], S21, 0xa9e3e905);
        d = round_2(d, a, b, c, block[2], S22, 0xfcefa3f8);
        c = round_2(c, d, a, b, block[7], S23, 0x676f02d9);
        b = round_2(b, c, d, a, block[12], S24, 0x8d2a4c8a);

        a = round_3(a, b, c, d, block[5], S31, 0xfffa3942);
        d = round_3(d, a, b, c, block[8], S32, 0x8771f681);
        c = round_3(c, d, a, b, block[11], S33, 0x6d9d6122);
        b = round_3(b, c, d, a, block[14], S34, 0xfde5380c);
        a = round_3(a, b, c, d, block[1], S31, 0xa4beea44);
        d = round_3(d, a, b, c, block[4], S32, 0x4bdecfa9);
        c = round_3(c, d, a, b, block[7], S33, 0xf6bb4b60);
        b = round_3(b, c, d, a, block[10], S34, 0xbebfbc70);
        a = round_3(a, b, c, d, block[13], S31, 0x289b7ec6);
        d = round_3(d, a, b, c, block[0], S32, 0xeaa127fa);
        c = round_3(c, d, a, b, block[3], S33, 0xd4ef3085);
        b = round_3(b, c, d, a, block[6], S34, 0x4881d05);
        a = round_3(a, b, c, d, block[9], S31, 0xd9d4d039);
        d = round_3(d, a, b, c, block[12], S32, 0xe6db99e5);
        c = round_3(c, d, a, b, block[15], S33, 0x1fa27cf8);
        b = round_3(b, c, d, a, block[2], S34, 0xc4ac5665);

        a = round_4(a, b, c, d, block[0], S41, 0xf4292244);
        d = round_4(d, a, b, c, block[7], S42, 0x432aff97);
        c = round_4(c, d, a, b, block[14], S43, 0xab9423a7);
        b = round_4(b, c, d, a, block[5], S44, 0xfc93a039);
        a = round_4(a, b, c, d, block[12], S41, 0x655b59c3);
        d = round_4(d, a, b, c, block[3], S42, 0x8f0ccc92);
        c = round_4(c, d, a, b, block[10], S43, 0xffeff47d);
        b = round_4(b, c, d, a, block[1], S44, 0x85845dd1);
        a = round_4(a, b, c, d, block[8], S41, 0x6fa87e4f);
        d = round_4(d, a, b, c, block[15], S42, 0xfe2ce6e0);
        c = round_4(c, d, a, b, block[6], S43, 0xa3014314);
        b = round_4(b, c, d, a, block[13], S44, 0x4e0811a1);
        a = round_4(a, b, c, d, block[4], S41, 0xf7537e82);
        d = round_4(d, a, b, c, block[11], S42, 0xbd3af235);
        c = round_4(c, d, a, b, block[2], S43, 0x2ad7d2bb);
        b = round_4(b, c, d, a, block[9], S44, 0xeb86d391);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[inline(always)]
fn hash_1(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

#[inline(always)]
fn hash_2(x: u32, y: u32, z: u32) -> u32 {
    x & z | y & !z
}

#[inline(always)]
fn hash_3(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn hash_4(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

#[inline(always)]
fn round_1(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    hash_1(b, c, d)
        .wrapping_add(x)
        .wrapping_add(ac)
        .wrapping_add(a)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn round_2(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    hash_2(b, c, d)
        .wrapping_add(x)
        .wrapping_add(ac)
        .wrapping_add(a)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn round_3(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    hash_3(b, c, d)
        .wrapping_add(x)
        .wrapping_add(ac)
        .wrapping_add(a)
        .rotate_left(s)
        .wrapping_add(b)
}

#[inline(always)]
fn round_4(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32, ac: u32) -> u32 {
    hash_4(b, c, d)
        .wrapping_add(x)
        .wrapping_add(ac)
        .wrapping_add(a)
        .rotate_left(s)
        .wrapping_add(b)
}

const S11: u32 = 7;
const S12: u32 = 12;
const S13: u32 = 17;
const S14: u32 = 22;
const S21: u32 = 5;
const S22: u32 = 9;
const S23: u32 = 14;
const S24: u32 = 20;
const S31: u32 = 4;
const S32: u32 = 11;
const S33: u32 = 16;
const S34: u32 = 23;
const S41: u32 = 6;
const S42: u32 = 10;
const S43: u32 = 15;
const S44: u32 = 21;

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::{
        tester::{HasherTestWrapper, TestData},
        Hasher,
    };

    use super::MD5;

    const TESTS: &[TestData] = &[
        TestData {
            data: "".as_bytes(),
            repeat: 1,
            result: "d41d8cd98f00b204e9800998ecf8427e",
        },
        TestData {
            data: "a".as_bytes(),
            repeat: 1,
            result: "0cc175b9c0f1b6a831c399e269772661",
        },
        TestData {
            data: "abc".as_bytes(),
            repeat: 1,
            result: "900150983cd24fb0d6963f7d28e17f72",
        },
        TestData {
            data: "message digest".as_bytes(),
            repeat: 1,
            result: "f96b697d7cb7938d525a2f31aaf161d0",
        },
        TestData {
            data: "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            repeat: 1,
            result: "c3fcd3d76192e4007dfb496cca67e13b",
        },
        TestData {
            data: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            repeat: 1,
            result: "d174ab98d277d9f5a5611c2c9f419d9f",
        },
        TestData {
            data:
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    .as_bytes(),
            repeat: 1,
            result: "57edf4a22be3c955ac49da2e2107b67a",
        },
    ];

    #[test]
    fn tests_from_rfc() {
        HasherTestWrapper::new(MD5::new()).run_tests(TESTS);
    }

    #[test]
    #[should_panic]
    fn panic_test1() {
        let mut hasher = MD5::new();
        hasher
            .update("Not multiple of block size".as_bytes())
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn panic_test2() {
        let mut hasher = MD5::new();
        let data = [0u8; MD5::BLOCK_SIZE + 1];
        hasher.update_last(&data).unwrap();
    }
}
