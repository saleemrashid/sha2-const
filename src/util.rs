/// Copies `n` bytes from `src` (starting at `src_offset`) to `dest` (starting
/// at `dest_offset`).
///
/// The source and destination must _not_ overlap. This function exists because
/// subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn memcpy<const N: usize>(
    mut dest: [u8; N],
    dest_offset: usize,
    src: &[u8],
    src_offset: usize,
    n: usize,
) -> [u8; N] {
    let mut i = 0;
    while i < n {
        dest[dest_offset + i] = src[src_offset + i];
        i += 1;
    }
    dest
}

/// Sets `n` bytes in `dest` (starting at `dest_offset`) to `val`.
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn memset<const N: usize>(
    mut dest: [u8; N],
    offset: usize,
    val: u8,
    n: usize,
) -> [u8; N] {
    let mut i = 0;
    while i < n {
        dest[offset + i] = val;
        i += 1;
    }
    dest
}

/// Loads an unsigned 32-bit big endian integer from `src` (starting at
/// `offset`).
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn load_u32_be(src: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        src[offset],
        src[offset + 1],
        src[offset + 2],
        src[offset + 3],
    ])
}

/// Loads an unsigned 64-bit big endian integer from `src` (starting at
/// `offset`).
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn load_u64_be(src: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        src[offset],
        src[offset + 1],
        src[offset + 2],
        src[offset + 3],
        src[offset + 4],
        src[offset + 5],
        src[offset + 6],
        src[offset + 7],
    ])
}

/// Stores an unsigned 32-bit big endian integer into `dest` (starting at
/// `offset`).
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn store_u32_be<const N: usize>(dest: [u8; N], offset: usize, n: u32) -> [u8; N] {
    let bytes = u32::to_be_bytes(n);
    memcpy(dest, offset, &bytes, 0, bytes.len())
}

/// Stores an unsigned 64-bit big endian integer into `dest` (starting at
/// `offset`).
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn store_u64_be<const N: usize>(dest: [u8; N], offset: usize, n: u64) -> [u8; N] {
    let bytes = u64::to_be_bytes(n);
    memcpy(dest, offset, &bytes, 0, bytes.len())
}

/// Stores an unsigned 128-bit big endian integer into `dest` (starting at
/// `offset`).
///
/// This function exists because subslices are not supported in `const fn`.
#[inline(always)]
pub(crate) const fn store_u128_be<const N: usize>(
    dest: [u8; N],
    offset: usize,
    n: u128,
) -> [u8; N] {
    let bytes = u128::to_be_bytes(n);
    memcpy(dest, offset, &bytes, 0, bytes.len())
}
