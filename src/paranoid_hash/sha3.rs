use std::mem::size_of;

use ambassador::Delegate;

use crate::{
    paranoid_hash::{hash_helper::slice_as_chunks, Hasher},
    Error, Result,
};

macro_rules! impl_common {
    ( $struct:ty, $base:ty ) => {
        impl $struct {
            pub const BLOCK_SIZE: usize = <$base>::BLOCK_SIZE;
            pub const DIGEST_SIZE: usize = <$base>::DIGEST_SIZE;

            pub const fn new() -> Self {
                Self(<$base>::new())
            }
        }
    };
}

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA3_224(
    SHA3Core<{ SHA3_224_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_224_CAPACITY) / 8 }>,
);
impl_common!(SHA3_224,
    SHA3Core<{ SHA3_224_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_224_CAPACITY) / 8 }>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA3_256(
    SHA3Core<{ SHA3_256_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_256_CAPACITY) / 8 }>,
);
impl_common!(SHA3_256,
    SHA3Core<{ SHA3_256_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_256_CAPACITY) / 8 }>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA3_384(
    SHA3Core<{ SHA3_384_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_384_CAPACITY) / 8 }>,
);
impl_common!(SHA3_384,
    SHA3Core<{ SHA3_384_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_384_CAPACITY) / 8 }>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA3_512(
    SHA3Core<{ SHA3_512_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_512_CAPACITY) / 8 }>,
);
impl_common!(SHA3_512,
        SHA3Core<{ SHA3_512_CAPACITY / 2 / 8 }, { (STATE_SIZE - SHA3_512_CAPACITY) / 8 }>);

// DIGEST_SIZE = CAPACITY / 2 / 8
// RATE_IN_U8 = (STATE_SIZE - CAPACITY) / 8
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SHA3Core<const DIGEST_SIZE: usize, const RATE_IN_U8: usize> {
    state: [u64; STATE_SIZE / 8 / size_of::<u64>()],
    is_done: bool,
    digest: [u8; DIGEST_SIZE],

    temp: [u8; RATE_IN_U8],
    pointer: usize,
}

impl<const DIGEST_SIZE: usize, const RATE_IN_U8: usize> SHA3Core<DIGEST_SIZE, RATE_IN_U8> {
    const BLOCK_SIZE: usize = RATE_IN_U8;
    const DIGEST_SIZE: usize = DIGEST_SIZE;

    const fn new() -> Self {
        Self {
            state: [0; STATE_SIZE / 8 / size_of::<u64>()],
            is_done: false,
            digest: [0; DIGEST_SIZE],
            temp: [0; RATE_IN_U8],
            pointer: 0,
        }
    }

    #[inline(always)]
    fn update_rate_block(&mut self, rate_block: &[u8]) {
        let mut block = [0u64; SLICE_SIZE];
        for (c, b) in slice_as_chunks(rate_block).iter().zip(block.iter_mut()) {
            *b = u64::from_le_bytes(*c);
        }

        for (s, b) in self.state.iter_mut().zip(block.iter()) {
            *s ^= *b;
        }

        keccak_f(&mut self.state);
    }
}

impl<const DIGEST_SIZE: usize, const RATE_IN_U8: usize> Hasher
    for SHA3Core<DIGEST_SIZE, RATE_IN_U8>
{
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        let mut chunks = if self.pointer == 0 {
            data.chunks_exact(RATE_IN_U8)
        } else {
            let mut copied = 0;
            for (t, d) in self.temp[self.pointer..].iter_mut().zip(data.iter()) {
                *t = *d;
                copied += 1;
            }

            self.pointer += copied;

            if self.pointer == self.temp.len() {
                self.pointer = 0;

                let temp = self.temp;

                self.update_rate_block(&temp);
            }

            data[copied..].chunks_exact(RATE_IN_U8)
        };

        for chunk in &mut chunks {
            self.update_rate_block(chunk);
        }

        self.temp[self.pointer..self.pointer + chunks.remainder().len()]
            .copy_from_slice(chunks.remainder());

        self.pointer += chunks.remainder().len();

        Ok(())
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)?;

        if self.temp.len() - self.pointer == 1 {
            self.temp[self.pointer] = 0b01100001u8.reverse_bits();
        } else {
            self.temp[self.pointer] = 0b01100000u8.reverse_bits();
            self.temp[self.pointer + 1..].fill(0);
            self.temp[self.temp.len() - 1] = 0b00000001u8.reverse_bits();
        }

        let temp = self.temp;

        self.update_rate_block(&temp);

        for (d, s) in self.digest.chunks_mut(8).zip(self.state.iter()) {
            let bytes = s.to_le_bytes();
            d.copy_from_slice(&bytes[..d.len()]);
        }

        self.is_done = true;

        Ok(())
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

impl<const DIGEST_SIZE: usize, const RATE_IN_U8: usize> Default
    for SHA3Core<DIGEST_SIZE, RATE_IN_U8>
{
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn theta(a: &mut [u64; SLICE_SIZE]) {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }

    let mut d = [0u64; 5];
    for x in 0..5isize {
        d[x as usize] = c[(x - 1).wrapping_rem_euclid(5) as usize]
            ^ c[(x + 1).rem_euclid(5) as usize].rotate_left(1);
    }

    for y in 0..5 {
        for x in 0..5 {
            a[x + y * 5] ^= d[x];
        }
    }
}

#[inline(always)]
fn rho(a: &mut [u64; SLICE_SIZE]) {
    for t in 0..24 {
        let index = RHO_INDICES[t];
        unsafe {
            *a.get_unchecked_mut(index) = a.get_unchecked(index).rotate_left(RHO_OFFSETS[t]);
        }
    }
}

#[inline(always)]
fn pi(a: &mut [u64; SLICE_SIZE]) {
    let mut a_prime = [0; SLICE_SIZE];

    for y in 0..5 {
        for x in 0..5 {
            a_prime[x + y * 5] = a[(x + 3 * y) % 5 + x * 5];
        }
    }

    *a = a_prime;
}

#[inline(always)]
fn chi(a: &mut [u64; SLICE_SIZE]) {
    let mut a_prime = [0; SLICE_SIZE];

    for y in 0..5 {
        for x in 0..5 {
            a_prime[x + y * 5] = a[x + y * 5] ^ !a[(x + 1) % 5 + y * 5] & a[(x + 2) % 5 + y * 5];
        }
    }

    *a = a_prime;
}

#[inline(always)]
fn iota(a: &mut [u64; SLICE_SIZE], i: usize) {
    let rc = unsafe { *RC_TABLE.get_unchecked(i) };

    a[0] ^= rc;
}

#[inline(always)]
fn keccak_f(a: &mut [u64; SLICE_SIZE]) {
    for i in 0..ROUND_COUNT {
        theta(a);
        rho(a);
        pi(a);
        chi(a);
        iota(a, i);
    }
}

const fn rho_indices() -> [usize; 24] {
    let mut table = [0; 24];

    let mut x = 1;
    let mut y = 0;

    let mut t = 0;
    while t < 24 {
        table[t] = x + y * 5;
        let old_y = y;
        y = (2 * x + 3 * y) % 5;
        x = old_y;

        t += 1;
    }

    table
}

const fn rho_right_shift_offsets() -> [u32; 24] {
    let mut table = [0; 24];

    let mut t = 0;
    while t < 24 {
        table[t as usize] = ((t + 1) * (t + 2)) / 2;

        t += 1;
    }

    table
}

const fn rc_table() -> [u64; ROUND_COUNT] {
    let mut switch_table = [0; 255];
    switch_table[0] = 1;
    let mut t = 1;
    while t < 255 {
        let mut i = 1;
        let mut r = [0, 1, 0, 0, 0, 0, 0, 0, 0];
        while i <= t {
            r[0] = 0;

            r[0] ^= r[8];
            r[4] ^= r[8];
            r[5] ^= r[8];
            r[6] ^= r[8];
            let mut ri = 8;
            while ri > 0 {
                r[ri] = r[ri - 1];

                ri -= 1;
            }

            i += 1;
        }

        switch_table[t] = r[1];

        t += 1;
    }

    let mut rc_table = [0u64; ROUND_COUNT];
    let mut i = 0;
    while i < ROUND_COUNT {
        let mut rc = 0;
        let mut j = 0;
        while j <= E {
            rc |= (1u64 << (2usize.pow(j as u32) - 1)) * switch_table[j + 7 * i];

            j += 1;
        }

        rc_table[i] = rc;

        i += 1;
    }

    rc_table
}

const STATE_SIZE: usize = 1600;
const SLICE_SIZE: usize = 5 * 5;
// log2(STATE_SIZE / SLICE_SIZE)
const E: usize = 6;
const ROUND_COUNT: usize = 24;

const RHO_INDICES: [usize; 24] = rho_indices();
const RHO_OFFSETS: [u32; 24] = rho_right_shift_offsets();
const RC_TABLE: [u64; ROUND_COUNT] = rc_table();

const SHA3_224_CAPACITY: usize = 448;
const SHA3_256_CAPACITY: usize = 512;
const SHA3_384_CAPACITY: usize = 768;
const SHA3_512_CAPACITY: usize = 1024;

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::tester::HasherTestWrapper;
    use crate::paranoid_hash::tester::TestData;

    use super::SHA3_224;
    use super::SHA3_256;
    use super::SHA3_384;
    use super::SHA3_512;

    const SHA3_224_TESTS: &[TestData] = &[
        TestData {
            data: &[],
            repeat: 1,
            result: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        },
        TestData {
            data: &[0xa3],
            repeat: 200,
            result: "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0",
        },
    ];

    const SHA3_256_TESTS: &[TestData] = &[
        TestData {
            data: &[],
            repeat: 1,
            result: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        },
        TestData {
            data: &[0xa3],
            repeat: 200,
            result: "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
        },
    ];

    const SHA3_384_TESTS: &[TestData] = &[
        TestData {
            data: &[],
            repeat: 1,
            result: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        },
        TestData {
            data: &[0xa3],
            repeat: 200,
            result: "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f",
        },
    ];

    const SHA3_512_TESTS: &[TestData] = &[
        TestData {
            data: &[],
            repeat: 1,
            result: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        },
        TestData {
            data: &[0xa3],
            repeat: 200,
            result: "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00",
        },
    ];

    #[test]
    fn tests_from_nist() {
        HasherTestWrapper::new(SHA3_224::new()).run_tests(SHA3_224_TESTS);

        HasherTestWrapper::new(SHA3_256::new()).run_tests(SHA3_256_TESTS);

        HasherTestWrapper::new(SHA3_384::new()).run_tests(SHA3_384_TESTS);

        HasherTestWrapper::new(SHA3_512::new()).run_tests(SHA3_512_TESTS);
    }
}
