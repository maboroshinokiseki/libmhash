use std::{mem::size_of, ops::Shr};

use ambassador::Delegate;

use crate::{paranoid_hash::Hasher, Error, Result};

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

macro_rules! update_block {
    ( $self:expr, $block:expr, $round:expr, $k:expr ) => {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = $self.state;

        let mut words: [Self::Word; $round] = [0; $round];
        words[0..$block.len()].copy_from_slice($block);
        for i in $block.len()..$round {
            words[i] = Self::ssigma1(words[i - 2])
                .wrapping_add(words[i - 7])
                .wrapping_add(Self::ssigma0(words[i - 15]))
                .wrapping_add(words[i - 16]);
        }

        for i in 0..$round {
            let t1 = h
                .wrapping_add(Self::bsigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add($k[i])
                .wrapping_add(words[i]);
            let t2 = Self::bsigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        $self.state[0] = a.wrapping_add($self.state[0]);
        $self.state[1] = b.wrapping_add($self.state[1]);
        $self.state[2] = c.wrapping_add($self.state[2]);
        $self.state[3] = d.wrapping_add($self.state[3]);
        $self.state[4] = e.wrapping_add($self.state[4]);
        $self.state[5] = f.wrapping_add($self.state[5]);
        $self.state[6] = g.wrapping_add($self.state[6]);
        $self.state[7] = h.wrapping_add($self.state[7]);
    };
}

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_224(SHA2_256Core<224>);
impl_common!(SHA2_224, SHA2_256Core<224>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_256(SHA2_256Core<256>);
impl_common!(SHA2_256, SHA2_256Core<256>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_384(SHA2_512Core<384>);
impl_common!(SHA2_384, SHA2_512Core<384>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_512(SHA2_512Core<512>);
impl_common!(SHA2_512, SHA2_512Core<512>);

trait SHA2Core {
    type Word;
    type Count;

    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;
    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD];

    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word;
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word;
    fn bsigma0(x: Self::Word) -> Self::Word;
    fn bsigma1(x: Self::Word) -> Self::Word;
    fn ssigma0(x: Self::Word) -> Self::Word;
    fn ssigma1(x: Self::Word) -> Self::Word;
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]);
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SHA2_256Core<const LENGTH: usize> {
    state: [u32; STATE_SIZE_IN_WORD],
    count: u64,
    is_done: bool,
    digest: [u8; SHA256_DIGEST_SIZE],
}

impl<const LENGTH: usize> SHA2_256Core<LENGTH> {
    const fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            count: 0,
            is_done: false,
            digest: [0u8; SHA256_DIGEST_SIZE],
        }
    }
}

impl<const LENGTH: usize> SHA2Core for SHA2_256Core<LENGTH> {
    type Word = u32;

    type Count = u64;

    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;

    const DIGEST_SIZE: usize = LENGTH / 8;

    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD] = match LENGTH {
        224 => SHA224_INITIAL,
        256 => SHA256_INITIAL,
        _ => panic!("Invalid length"),
    };

    #[inline]
    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y ^ z)) ^ z
    }

    #[inline]
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y | z)) | (y & z)
    }

    #[inline]
    fn bsigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn bsigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn ssigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(7) ^ x.rotate_right(18) ^ x.shr(3)
    }

    #[inline]
    fn ssigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(17) ^ x.rotate_right(19) ^ x.shr(10)
    }

    #[inline]
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]) {
        update_block!(self, block, SHA256_ROUND_COUNT, K256);
    }
}

impl<const LENGTH: usize> Hasher for SHA2_256Core<LENGTH> {
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, SHA256_BLOCK_SIZE, u32, u64, "checked", "be");
    }

    #[inline]
    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, SHA256_BLOCK_SIZE, u32, u64, "checked", "be");
    }

    #[inline]
    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest[..Self::DIGEST_SIZE])
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::new();
    }

    #[inline]
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    #[inline]
    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SHA2_512Core<const LENGTH: usize> {
    state: [u64; STATE_SIZE_IN_WORD],
    count: u128,
    is_done: bool,
    digest: [u8; SHA512_DIGEST_SIZE],
}

impl<const LENGTH: usize> SHA2_512Core<LENGTH> {
    const fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            count: 0,
            is_done: false,
            digest: [0u8; SHA512_DIGEST_SIZE],
        }
    }
}

impl<const LENGTH: usize> SHA2Core for SHA2_512Core<LENGTH> {
    type Word = u64;

    type Count = u128;

    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;

    const DIGEST_SIZE: usize = LENGTH / 8;

    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD] = match LENGTH {
        384 => SHA384_INITIAL,
        512 => SHA512_INITIAL,
        _ => panic!("Invalid length"),
    };

    #[inline]
    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y ^ z)) ^ z
    }

    #[inline]
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y | z)) | (y & z)
    }

    #[inline]
    fn bsigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline]
    fn bsigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline]
    fn ssigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(1) ^ x.rotate_right(8) ^ x.shr(7)
    }

    #[inline]
    fn ssigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(19) ^ x.rotate_right(61) ^ x.shr(6)
    }

    #[inline]
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]) {
        update_block!(self, block, SHA512_ROUND_COUNT, K512);
    }
}

impl<const LENGTH: usize> Hasher for SHA2_512Core<LENGTH> {
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, SHA512_BLOCK_SIZE, u64, u128, "checked", "be");
    }

    #[inline]
    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, SHA512_BLOCK_SIZE, u64, u128, "checked", "be");
    }

    #[inline]
    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest[..Self::DIGEST_SIZE])
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::new();
    }

    #[inline]
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    #[inline]
    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

impl<const LENGTH: usize> Default for SHA2_512Core<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

const STATE_SIZE_IN_WORD: usize = 8;
const BLOCK_SIZE_IN_WORD: usize = 16;
const SHA256_BLOCK_SIZE: usize = 64;
const SHA512_BLOCK_SIZE: usize = 128;
const SHA256_DIGEST_SIZE: usize = 256 / 8;
const SHA512_DIGEST_SIZE: usize = 512 / 8;
const SHA256_ROUND_COUNT: usize = 64;
const SHA512_ROUND_COUNT: usize = 80;

const SHA224_INITIAL: [u32; STATE_SIZE_IN_WORD] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

const SHA256_INITIAL: [u32; STATE_SIZE_IN_WORD] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA384_INITIAL: [u64; STATE_SIZE_IN_WORD] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const SHA512_INITIAL: [u64; STATE_SIZE_IN_WORD] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const K256: [u32; SHA256_ROUND_COUNT] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; SHA512_ROUND_COUNT] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::tester::HasherTestWrapper;
    use crate::paranoid_hash::tester::TestData;

    use super::SHA2_224;
    use super::SHA2_256;
    use super::SHA2_384;
    use super::SHA2_512;

    const TEST1: &[u8] = "abc".as_bytes();
    const TEST2_1: &[u8] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    const TEST2_2: &[u8] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    const TEST3: &[u8] = "a".as_bytes();
    const TEST4: &[u8] =
        "0123456701234567012345670123456701234567012345670123456701234567".as_bytes();
    const TEST8_224: &[u8] = &[
        0x18, 0x80, 0x40, 0x05, 0xdd, 0x4f, 0xbd, 0x15, 0x56, 0x29, 0x9d, 0x6f, 0x9d, 0x93, 0xdf,
        0x62,
    ];
    const TEST10_224: &[u8] = &[
        0x55, 0xb2, 0x10, 0x07, 0x9c, 0x61, 0xb5, 0x3a, 0xdd, 0x52, 0x06, 0x22, 0xd1, 0xac, 0x97,
        0xd5, 0xcd, 0xbe, 0x8c, 0xb3, 0x3a, 0xa0, 0xae, 0x34, 0x45, 0x17, 0xbe, 0xe4, 0xd7, 0xba,
        0x09, 0xab, 0xc8, 0x53, 0x3c, 0x52, 0x50, 0x88, 0x7a, 0x43, 0xbe, 0xbb, 0xac, 0x90, 0x6c,
        0x2e, 0x18, 0x37, 0xf2, 0x6b, 0x36, 0xa5, 0x9a, 0xe3, 0xbe, 0x78, 0x14, 0xd5, 0x06, 0x89,
        0x6b, 0x71, 0x8b, 0x2a, 0x38, 0x3e, 0xcd, 0xac, 0x16, 0xb9, 0x61, 0x25, 0x55, 0x3f, 0x41,
        0x6f, 0xf3, 0x2c, 0x66, 0x74, 0xc7, 0x45, 0x99, 0xa9, 0x00, 0x53, 0x86, 0xd9, 0xce, 0x11,
        0x12, 0x24, 0x5f, 0x48, 0xee, 0x47, 0x0d, 0x39, 0x6c, 0x1e, 0xd6, 0x3b, 0x92, 0x67, 0x0c,
        0xa5, 0x6e, 0xc8, 0x4d, 0xee, 0xa8, 0x14, 0xb6, 0x13, 0x5e, 0xca, 0x54, 0x39, 0x2b, 0xde,
        0xdb, 0x94, 0x89, 0xbc, 0x9b, 0x87, 0x5a, 0x8b, 0xaf, 0x0d, 0xc1, 0xae, 0x78, 0x57, 0x36,
        0x91, 0x4a, 0xb7, 0xda, 0xa2, 0x64, 0xbc, 0x07, 0x9d, 0x26, 0x9f, 0x2c, 0x0d, 0x7e, 0xdd,
        0xd8, 0x10, 0xa4, 0x26, 0x14, 0x5a, 0x07, 0x76, 0xf6, 0x7c, 0x87, 0x82, 0x73,
    ];
    const TEST8_256: &[u8] = &[
        0xe3, 0xd7, 0x25, 0x70, 0xdc, 0xdd, 0x78, 0x7c, 0xe3, 0x88, 0x7a, 0xb2, 0xcd, 0x68, 0x46,
        0x52,
    ];
    const TEST10_256: &[u8] = &[
        0x83, 0x26, 0x75, 0x4e, 0x22, 0x77, 0x37, 0x2f, 0x4f, 0xc1, 0x2b, 0x20, 0x52, 0x7a, 0xfe,
        0xf0, 0x4d, 0x8a, 0x05, 0x69, 0x71, 0xb1, 0x1a, 0xd5, 0x71, 0x23, 0xa7, 0xc1, 0x37, 0x76,
        0x00, 0x00, 0xd7, 0xbe, 0xf6, 0xf3, 0xc1, 0xf7, 0xa9, 0x08, 0x3a, 0xa3, 0x9d, 0x81, 0x0d,
        0xb3, 0x10, 0x77, 0x7d, 0xab, 0x8b, 0x1e, 0x7f, 0x02, 0xb8, 0x4a, 0x26, 0xc7, 0x73, 0x32,
        0x5f, 0x8b, 0x23, 0x74, 0xde, 0x7a, 0x4b, 0x5a, 0x58, 0xcb, 0x5c, 0x5c, 0xf3, 0x5b, 0xce,
        0xe6, 0xfb, 0x94, 0x6e, 0x5b, 0xd6, 0x94, 0xfa, 0x59, 0x3a, 0x8b, 0xeb, 0x3f, 0x9d, 0x65,
        0x92, 0xec, 0xed, 0xaa, 0x66, 0xca, 0x82, 0xa2, 0x9d, 0x0c, 0x51, 0xbc, 0xf9, 0x33, 0x62,
        0x30, 0xe5, 0xd7, 0x84, 0xe4, 0xc0, 0xa4, 0x3f, 0x8d, 0x79, 0xa3, 0x0a, 0x16, 0x5c, 0xba,
        0xbe, 0x45, 0x2b, 0x77, 0x4b, 0x9c, 0x71, 0x09, 0xa9, 0x7d, 0x13, 0x8f, 0x12, 0x92, 0x28,
        0x96, 0x6f, 0x6c, 0x0a, 0xdc, 0x10, 0x6a, 0xad, 0x5a, 0x9f, 0xdd, 0x30, 0x82, 0x57, 0x69,
        0xb2, 0xc6, 0x71, 0xaf, 0x67, 0x59, 0xdf, 0x28, 0xeb, 0x39, 0x3d, 0x54, 0xd6,
    ];
    const TEST8_384: &[u8] = &[
        0xa4, 0x1c, 0x49, 0x77, 0x79, 0xc0, 0x37, 0x5f, 0xf1, 0x0a, 0x7f, 0x4e, 0x08, 0x59, 0x17,
        0x39,
    ];
    const TEST10_384: &[u8] = &[
        0x39, 0x96, 0x69, 0xe2, 0x8f, 0x6b, 0x9c, 0x6d, 0xbc, 0xbb, 0x69, 0x12, 0xec, 0x10, 0xff,
        0xcf, 0x74, 0x79, 0x03, 0x49, 0xb7, 0xdc, 0x8f, 0xbe, 0x4a, 0x8e, 0x7b, 0x3b, 0x56, 0x21,
        0xdb, 0x0f, 0x3e, 0x7d, 0xc8, 0x7f, 0x82, 0x32, 0x64, 0xbb, 0xe4, 0x0d, 0x18, 0x11, 0xc9,
        0xea, 0x20, 0x61, 0xe1, 0xc8, 0x4a, 0xd1, 0x0a, 0x23, 0xfa, 0xc1, 0x72, 0x7e, 0x72, 0x02,
        0xfc, 0x3f, 0x50, 0x42, 0xe6, 0xbf, 0x58, 0xcb, 0xa8, 0xa2, 0x74, 0x6e, 0x1f, 0x64, 0xf9,
        0xb9, 0xea, 0x35, 0x2c, 0x71, 0x15, 0x07, 0x05, 0x3c, 0xf4, 0xe5, 0x33, 0x9d, 0x52, 0x86,
        0x5f, 0x25, 0xcc, 0x22, 0xb5, 0xe8, 0x77, 0x84, 0xa1, 0x2f, 0xc9, 0x61, 0xd6, 0x6c, 0xb6,
        0xe8, 0x95, 0x73, 0x19, 0x9a, 0x2c, 0xe6, 0x56, 0x5c, 0xbd, 0xf1, 0x3d, 0xca, 0x40, 0x38,
        0x32, 0xcf, 0xcb, 0x0e, 0x8b, 0x72, 0x11, 0xe8, 0x3a, 0xf3, 0x2a, 0x11, 0xac, 0x17, 0x92,
        0x9f, 0xf1, 0xc0, 0x73, 0xa5, 0x1c, 0xc0, 0x27, 0xaa, 0xed, 0xef, 0xf8, 0x5a, 0xad, 0x7c,
        0x2b, 0x7c, 0x5a, 0x80, 0x3e, 0x24, 0x04, 0xd9, 0x6d, 0x2a, 0x77, 0x35, 0x7b, 0xda, 0x1a,
        0x6d, 0xae, 0xed, 0x17, 0x15, 0x1c, 0xb9, 0xbc, 0x51, 0x25, 0xa4, 0x22, 0xe9, 0x41, 0xde,
        0x0c, 0xa0, 0xfc, 0x50, 0x11, 0xc2, 0x3e, 0xcf, 0xfe, 0xfd, 0xd0, 0x96, 0x76, 0x71, 0x1c,
        0xf3, 0xdb, 0x0a, 0x34, 0x40, 0x72, 0x0e, 0x16, 0x15, 0xc1, 0xf2, 0x2f, 0xbc, 0x3c, 0x72,
        0x1d, 0xe5, 0x21, 0xe1, 0xb9, 0x9b, 0xa1, 0xbd, 0x55, 0x77, 0x40, 0x86, 0x42, 0x14, 0x7e,
        0xd0, 0x96,
    ];
    const TEST8_512: &[u8] = &[
        0x8d, 0x4e, 0x3c, 0x0e, 0x38, 0x89, 0x19, 0x14, 0x91, 0x81, 0x6e, 0x9d, 0x98, 0xbf, 0xf0,
        0xa0,
    ];
    const TEST10_512: &[u8] = &[
        0xa5, 0x5f, 0x20, 0xc4, 0x11, 0xaa, 0xd1, 0x32, 0x80, 0x7a, 0x50, 0x2d, 0x65, 0x82, 0x4e,
        0x31, 0xa2, 0x30, 0x54, 0x32, 0xaa, 0x3d, 0x06, 0xd3, 0xe2, 0x82, 0xa8, 0xd8, 0x4e, 0x0d,
        0xe1, 0xde, 0x69, 0x74, 0xbf, 0x49, 0x54, 0x69, 0xfc, 0x7f, 0x33, 0x8f, 0x80, 0x54, 0xd5,
        0x8c, 0x26, 0xc4, 0x93, 0x60, 0xc3, 0xe8, 0x7a, 0xf5, 0x65, 0x23, 0xac, 0xf6, 0xd8, 0x9d,
        0x03, 0xe5, 0x6f, 0xf2, 0xf8, 0x68, 0x00, 0x2b, 0xc3, 0xe4, 0x31, 0xed, 0xc4, 0x4d, 0xf2,
        0xf0, 0x22, 0x3d, 0x4b, 0xb3, 0xb2, 0x43, 0x58, 0x6e, 0x1a, 0x7d, 0x92, 0x49, 0x36, 0x69,
        0x4f, 0xcb, 0xba, 0xf8, 0x8d, 0x95, 0x19, 0xe4, 0xeb, 0x50, 0xa6, 0x44, 0xf8, 0xe4, 0xf9,
        0x5e, 0xb0, 0xea, 0x95, 0xbc, 0x44, 0x65, 0xc8, 0x82, 0x1a, 0xac, 0xd2, 0xfe, 0x15, 0xab,
        0x49, 0x81, 0x16, 0x4b, 0xbb, 0x6d, 0xc3, 0x2f, 0x96, 0x90, 0x87, 0xa1, 0x45, 0xb0, 0xd9,
        0xcc, 0x9c, 0x67, 0xc2, 0x2b, 0x76, 0x32, 0x99, 0x41, 0x9c, 0xc4, 0x12, 0x8b, 0xe9, 0xa0,
        0x77, 0xb3, 0xac, 0xe6, 0x34, 0x06, 0x4e, 0x6d, 0x99, 0x28, 0x35, 0x13, 0xdc, 0x06, 0xe7,
        0x51, 0x5d, 0x0d, 0x73, 0x13, 0x2e, 0x9a, 0x0d, 0xc6, 0xd3, 0xb1, 0xf8, 0xb2, 0x46, 0xf1,
        0xa9, 0x8a, 0x3f, 0xc7, 0x29, 0x41, 0xb1, 0xe3, 0xbb, 0x20, 0x98, 0xe8, 0xbf, 0x16, 0xf2,
        0x68, 0xd6, 0x4f, 0x0b, 0x0f, 0x47, 0x07, 0xfe, 0x1e, 0xa1, 0xa1, 0x79, 0x1b, 0xa2, 0xf3,
        0xc0, 0xc7, 0x58, 0xe5, 0xf5, 0x51, 0x86, 0x3a, 0x96, 0xc9, 0x49, 0xad, 0x47, 0xd7, 0xfb,
        0x40, 0xd2,
    ];

    const SHA2_224_TESTS: &[TestData] = &[
        TestData {
            data: TEST1,
            repeat: 1,
            result: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        },
        TestData {
            data: TEST2_1,
            repeat: 1,
            result: "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        },
        TestData {
            data: TEST3,
            repeat: 1000000,
            result: "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        },
        TestData {
            data: TEST4,
            repeat: 10,
            result: "567f69f168cd7844e65259ce658fe7aadfa25216e68eca0eb7ab8262",
        },
        TestData {
            data: &[0x07],
            repeat: 1,
            result: "00ecd5f138422b8ad74c9799fd826c531bad2fcabc7450bee2aa8c2a",
        },
        TestData {
            data: TEST8_224,
            repeat: 1,
            result: "df90d78aa78821c99b40ba4c966921accd8ffb1e98ac388e56191db1",
        },
        TestData {
            data: TEST10_224,
            repeat: 1,
            result: "0b31894ec8937ad9b91bdfbcba294d9adefaa18e09305e9f20d5c3a4",
        },
    ];

    const SHA2_256_TESTS: &[TestData] = &[
        TestData {
            data: TEST1,
            repeat: 1,
            result: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        },
        TestData {
            data: TEST2_1,
            repeat: 1,
            result: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        },
        TestData {
            data: TEST3,
            repeat: 1000000,
            result: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        },
        TestData {
            data: TEST4,
            repeat: 10,
            result: "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5",
        },
        TestData {
            data: &[0x19],
            repeat: 1,
            result: "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4",
        },
        TestData {
            data: TEST8_256,
            repeat: 1,
            result: "175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8",
        },
        TestData {
            data: TEST10_256,
            repeat: 1,
            result: "97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc",
        },
    ];

    const SHA2_384_TESTS: &[TestData] = &[
        TestData {
            data: TEST1,
            repeat: 1,
            result: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        },
        TestData {
            data: TEST2_2,
            repeat: 1,
            result: "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        },
        TestData {
            data: TEST3,
            repeat: 1000000,
            result: "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        },
        TestData {
            data: TEST4,
            repeat: 10,
            result: "2fc64a4f500ddb6828f6a3430b8dd72a368eb7f3a8322a70bc84275b9c0b3ab00d27a5cc3c2d224aa6b61a0d79fb4596",
        },
        TestData {
            data: &[0xb9],
            repeat: 1,
            result: "bc8089a19007c0b14195f4ecc74094fec64f01f90929282c2fb392881578208ad466828b1c6c283d2722cf0ad1ab6938",
        },
        TestData {
            data: TEST8_384,
            repeat: 1,
            result: "c9a68443a005812256b8ec76b00516f0dbb74fab26d665913f194b6ffb0e91ea9967566b58109cbc675cc208e4c823f7",
        },
        TestData {
            data: TEST10_384,
            repeat: 1,
            result: "4f440db1e6edd2899fa335f09515aa025ee177a79f4b4aaf38e42b5c4de660f5de8fb2a5b2fbd2a3cbffd20cff1288c0",
        },
    ];

    const SHA2_512_TESTS: &[TestData] = &[
        TestData {
            data: TEST1,
            repeat: 1,
            result: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        },
        TestData {
            data: TEST2_2,
            repeat: 1,
            result: "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        },
        TestData {
            data: TEST3,
            repeat: 1000000,
            result: "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        },
        TestData {
            data: TEST4,
            repeat: 10,
            result: "89d05ba632c699c31231ded4ffc127d5a894dad412c0e024db872d1abd2ba8141a0f85072a9be1e2aa04cf33c765cb510813a39cd5a84c4acaa64d3f3fb7bae9",
        },
        TestData {
            data: &[0xd0],
            repeat: 1,
            result: "9992202938e882e73e20f6b69e68a0a7149090423d93c81bab3f21678d4aceeee50e4e8cafada4c85a54ea8306826c4ad6e74cece9631bfa8a549b4ab3fbba15",
        },
        TestData {
            data: TEST8_512,
            repeat: 1,
            result: "cb0b67a4b8712cd73c9aabc0b199e9269b20844afb75acbdd1c153c9828924c3ddedaafe669c5fdd0bc66f630f6773988213eb1b16f517ad0de4b2f0c95c90f8",
        },
        TestData {
            data: TEST10_512,
            repeat: 1,
            result: "c665befb36da189d78822d10528cbf3b12b3eef726039909c1a16a270d48719377966b957a878e720584779a62825c18da26415e49a7176a894e7510fd1451f5",
        },
    ];

    #[test]
    fn tests_from_rfc() {
        HasherTestWrapper::new(SHA2_224::new()).run_tests(SHA2_224_TESTS);

        HasherTestWrapper::new(SHA2_256::new()).run_tests(SHA2_256_TESTS);

        HasherTestWrapper::new(SHA2_384::new()).run_tests(SHA2_384_TESTS);

        HasherTestWrapper::new(SHA2_512::new()).run_tests(SHA2_512_TESTS);
    }
}
