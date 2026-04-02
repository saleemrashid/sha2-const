use crate::{
    constants::{K256, K512},
    util::{array_as_chunks, array_as_chunks_mut, array_rsplit_array_mut, idx, slice_fill},
};
use core::mem;

macro_rules! sha {
    (
        $name:ident,
        $word:ty,
        $k:expr,
        $length:ty,
        $bsig0:expr,
        $bsig1:expr,
        $ssig0:expr,
        $ssig1:expr
    ) => {
        #[derive(Copy, Clone)]
        pub(crate) struct $name {
            state: [$word; 8],
            buffer: [u8; Self::BLOCK_SIZE],
            offset: usize,
            length: $length,
        }

        impl $name {
            /// The internal block size of the hash function.
            pub(crate) const BLOCK_SIZE: usize = 16 * mem::size_of::<$word>();
            /// The digest size of the hash function.
            const DIGEST_SIZE: usize = 8 * mem::size_of::<$word>();

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
                let unfilled = idx!(&mut self.buffer[self.offset..]);
                if unfilled.len() > input.len() {
                    idx!(&mut unfilled[..input.len()]).copy_from_slice(input);
                    self.offset += input.len();
                } else {
                    let (partial, remaining) = input.split_at(unfilled.len());
                    unfilled.copy_from_slice(partial);
                    Self::compress(&mut self.state, &self.buffer);

                    let (blocks, remaining) = remaining.as_chunks();

                    let mut i = 0;
                    while i < blocks.len() {
                        Self::compress(&mut self.state, &blocks[i]);
                        i += 1
                    }

                    idx!(&mut self.buffer[..remaining.len()]).copy_from_slice(remaining);
                    self.offset = remaining.len();
                }

                self.length += (input.len() as $length) * 8;
            }

            pub(crate) const fn finalize(mut self) -> [u8; Self::DIGEST_SIZE] {
                let unfilled = idx!(&mut self.buffer[self.offset..]);
                let Some((first, unfilled)) = unfilled.split_first_mut() else {
                    // The buffer cannot be full
                    unreachable!()
                };
                // Append bit "1"
                *first = 0x80;

                let (padding, length) = match unfilled.split_last_chunk_mut() {
                    // Length will be in the current block
                    Some(pair) => pair,
                    None => {
                        slice_fill(unfilled, 0);
                        Self::compress(&mut self.state, &self.buffer);
                        // Length will be in a new block
                        array_rsplit_array_mut(&mut self.buffer)
                    },
                };

                slice_fill(padding, 0);
                // Append length to end of block
                *length = self.length.to_be_bytes();
                Self::compress(&mut self.state, &self.buffer);

                let mut digest = [0; Self::DIGEST_SIZE];
                let (dest, []) = array_as_chunks_mut(&mut digest);

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

                let mut w = [0; $k.len()];
                let (src, []) = array_as_chunks(block);

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

                let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

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

                *state = [
                    state[0].wrapping_add(a),
                    state[1].wrapping_add(b),
                    state[2].wrapping_add(c),
                    state[3].wrapping_add(d),
                    state[4].wrapping_add(e),
                    state[5].wrapping_add(f),
                    state[6].wrapping_add(g),
                    state[7].wrapping_add(h),
                ]
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
