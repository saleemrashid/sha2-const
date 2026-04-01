use crate::{
    constants::{K256, K512},
    util::{idx, memset},
};
use core::mem;

macro_rules! sha {
    ($name:ident, $word:ty, $k:ident, $length:ty, $bsig0:tt, $bsig1:tt, $ssig0:tt, $ssig1:tt) => {
        #[derive(Copy, Clone)]
        pub(crate) struct $name {
            state: [$word; 8],
            buffer: [u8; 16 * mem::size_of::<$word>()],
            offset: usize,
            length: $length,
        }

        impl $name {
            /// The internal block size of the hash function.
            pub(crate) const BLOCK_SIZE: usize = 16 * Self::WORD_SIZE;
            const DIGEST_SIZE: usize = 8 * Self::WORD_SIZE;
            const LENGTH_OFFSET: usize = Self::BLOCK_SIZE - Self::LENGTH_SIZE;
            const LENGTH_SIZE: usize = mem::size_of::<$length>();
            const WORD_SIZE: usize = mem::size_of::<$word>();

            /// Construct a new instance.
            pub(crate) const fn new(state: [$word; 8]) -> Self {
                Self {
                    state,
                    buffer: [0; Self::BLOCK_SIZE],
                    offset: 0,
                    length: 0,
                }
            }

            /// Add input data to the hash context.
            pub(crate) const fn update(&mut self, input: &[u8]) {
                let needed = idx!(&mut self.buffer[self.offset..]);

                if needed.len() > input.len() {
                    idx!(&mut needed[..input.len()]).copy_from_slice(input);
                    self.offset += input.len();
                } else {
                    let (partial, remainder) = input.split_at(needed.len());
                    needed.copy_from_slice(partial);
                    Self::compress(&mut self.state, &self.buffer);

                    let (blocks, remainder) = remainder.as_chunks();

                    let mut i = 0;
                    while i < blocks.len() {
                        Self::compress(&mut self.state, &blocks[i]);
                        i += 1
                    }

                    idx!(&mut self.buffer[..remainder.len()]).copy_from_slice(remainder);
                    self.offset = remainder.len();
                }

                self.length += (input.len() as $length) * 8;
            }

            pub(crate) const fn finalize(mut self) -> [u8; Self::DIGEST_SIZE] {
                let mut offset = self.offset;
                // Append bit "1"
                self.buffer[offset] = 0x80;
                offset += 1;

                if offset > Self::LENGTH_OFFSET {
                    let padding = idx!(&mut self.buffer[offset..]);
                    memset(padding, 0);
                    Self::compress(&mut self.state, &self.buffer);
                    offset = 0;
                }

                let padding = idx!(&mut self.buffer[offset..Self::LENGTH_OFFSET]);
                memset(padding, 0);
                // Append length to end of block
                let length = idx!(&mut self.buffer[Self::LENGTH_OFFSET..]);
                length.copy_from_slice(idx!(&self.length.to_be_bytes()[..]));

                Self::compress(&mut self.state, &self.buffer);

                let mut digest = [0; Self::DIGEST_SIZE];
                let (dest, []) = digest.as_chunks_mut() else {
                    unreachable!()
                };

                let mut i = 0;
                while i < self.state.len() {
                    dest[i] = self.state[i].to_be_bytes();
                    i += 1
                }

                digest
            }

            /// SHA compression function.
            const fn compress(state: &mut [$word; 8], block: &[u8; Self::BLOCK_SIZE]) {
                #[inline(always)]
                const fn ch(x: $word, y: $word, z: $word) -> $word {
                    (x & y) ^ ((!x) & z)
                }
                #[inline(always)]
                const fn maj(x: $word, y: $word, z: $word) -> $word {
                    (x & y) ^ (x & z) ^ (y & z)
                }
                #[inline(always)]
                const fn big_sigma0(x: $word) -> $word {
                    x.rotate_right($bsig0.0) ^ x.rotate_right($bsig0.1) ^ x.rotate_right($bsig0.2)
                }
                #[inline(always)]
                const fn big_sigma1(x: $word) -> $word {
                    x.rotate_right($bsig1.0) ^ x.rotate_right($bsig1.1) ^ x.rotate_right($bsig1.2)
                }
                #[inline(always)]
                const fn sigma0(x: $word) -> $word {
                    x.rotate_right($ssig0.0) ^ x.rotate_right($ssig0.1) ^ (x >> $ssig0.2)
                }
                #[inline(always)]
                const fn sigma1(x: $word) -> $word {
                    x.rotate_right($ssig1.0) ^ x.rotate_right($ssig1.1) ^ (x >> $ssig1.2)
                }

                let mut w: [$word; $k.len()] = [0; $k.len()];
                let (src, []) = block.as_chunks() else {
                    unreachable!()
                };

                let mut i = 0;
                while i < 16 {
                    w[i] = <$word>::from_be_bytes(src[i]);
                    i += 1;
                }
                while i < $k.len() {
                    w[i] = sigma1(w[i - 2])
                        .wrapping_add(w[i - 7])
                        .wrapping_add(sigma0(w[i - 15]))
                        .wrapping_add(w[i - 16]);
                    i += 1;
                }

                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                let mut i = 0;
                while i < $k.len() {
                    let t1 = h
                        .wrapping_add(big_sigma1(e))
                        .wrapping_add(ch(e, f, g))
                        .wrapping_add($k[i])
                        .wrapping_add(w[i]);
                    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(t1);
                    d = c;
                    c = b;
                    b = a;
                    a = t1.wrapping_add(t2);

                    i += 1;
                }

                state[0] = state[0].wrapping_add(a);
                state[1] = state[1].wrapping_add(b);
                state[2] = state[2].wrapping_add(c);
                state[3] = state[3].wrapping_add(d);
                state[4] = state[4].wrapping_add(e);
                state[5] = state[5].wrapping_add(f);
                state[6] = state[6].wrapping_add(g);
                state[7] = state[7].wrapping_add(h);
            }
        }
    };
}

sha!(
    Sha256,
    u32,
    K256,
    u64,
    (2, 13, 22),
    (6, 11, 25),
    (7, 18, 3),
    (17, 19, 10)
);

sha!(
    Sha512,
    u64,
    K512,
    u128,
    (28, 34, 39),
    (14, 18, 41),
    (1, 8, 7),
    (19, 61, 6)
);
