use core::ops::{Range, RangeFrom, RangeFull, RangeTo};

pub(crate) struct __ConstSliceIndex<I>(pub(crate) I);

#[allow(dead_code)]
impl __ConstSliceIndex<Range<usize>> {
    #[inline]
    pub(crate) const fn index<'a, T>(&self, slice: &'a [T]) -> &'a [T] {
        let (slice, _) = slice.split_at(self.0.end);
        let (_, slice) = slice.split_at(self.0.start);
        slice
    }

    #[inline]
    pub(crate) const fn index_mut<'a, T>(&self, slice: &'a mut [T]) -> &'a mut [T] {
        let (slice, _) = slice.split_at_mut(self.0.end);
        let (_, slice) = slice.split_at_mut(self.0.start);
        slice
    }
}

#[allow(dead_code)]
impl __ConstSliceIndex<RangeFrom<usize>> {
    #[inline]
    pub(crate) const fn index<'a, T>(&self, slice: &'a [T]) -> &'a [T] {
        let (_, slice) = slice.split_at(self.0.start);
        slice
    }

    #[inline]
    pub(crate) const fn index_mut<'a, T>(&self, slice: &'a mut [T]) -> &'a mut [T] {
        let (_, slice) = slice.split_at_mut(self.0.start);
        slice
    }
}

#[allow(dead_code)]
impl __ConstSliceIndex<RangeTo<usize>> {
    #[inline]
    pub(crate) const fn index<'a, T>(&self, slice: &'a [T]) -> &'a [T] {
        let (slice, _) = slice.split_at(self.0.end);
        slice
    }

    #[inline]
    pub(crate) const fn index_mut<'a, T>(&self, slice: &'a mut [T]) -> &'a mut [T] {
        let (slice, _) = slice.split_at_mut(self.0.end);
        slice
    }
}

#[allow(dead_code)]
#[allow(clippy::unused_self)]
impl __ConstSliceIndex<RangeFull> {
    #[inline]
    pub(crate) const fn index<'a, T>(&self, slice: &'a [T]) -> &'a [T] {
        slice
    }

    #[inline]
    pub(crate) const fn index_mut<'a, T>(&self, slice: &'a mut [T]) -> &'a mut [T] {
        slice
    }
}

macro_rules! idx_inner {
    (@accum $mut:ident; ($($slice:tt)*) [ $index:expr ]) => {
        $crate::util::idx_inner!(@emit $mut; ($($slice)*), $index)
    };
    (@accum $mut:ident; ($($slice:tt)*) $next:tt $($tail:tt)+) => {
        $crate::util::idx_inner!(@accum $mut; ($($slice)* $next) $($tail)+)
    };
    (@emit ref; $slice:expr, $index:expr) => {
        // Use split_at as an identity function, to force autoref to &[T]
        $crate::util::__ConstSliceIndex($index).index($slice.split_at(0).1)
    };
    (@emit mut; $slice:expr, $index:expr) => {
        // Use split_at_mut as an identity function, to force autoref to &mut [T]
        $crate::util::__ConstSliceIndex($index).index_mut($slice.split_at_mut(0).1)
    };
}

pub(crate) use idx_inner;

/// Implements `Index` and `IndexMut` syntax for slices in `const fn`.
macro_rules! idx {
    (&mut $($tt:tt)*) => {
        $crate::util::idx_inner!(@accum mut; () $($tt)*)
    };
    (&$($tt:tt)*) => {
        $crate::util::idx_inner!(@accum ref; () $($tt)*)
    };
}

pub(crate) use idx;

/// Fills `slice` with `value`.
///
/// This function exists because `slice::fill` is not `const fn`.
#[inline]
pub(crate) const fn slice_fill<T: Copy>(slice: &mut [T], value: T) {
    let mut i = 0;
    while i < slice.len() {
        slice[i] = value;
        i += 1;
    }
}

/// Splits the array into a slice of `D`-element arrays, starting at the
/// beginning of the array, and a remainder `R`-element array.
#[inline]
pub(crate) const fn array_as_chunks<T, const N: usize, const D: usize, const R: usize>(
    array: &[T; N],
) -> (&[[T; D]], &[T; R]) {
    const { assert!(N % D == R) };
    let (init, tail) = array_rsplit_array_ref(array);
    let (chunks, []) = init.as_chunks() else {
        unreachable!()
    };
    (chunks, tail)
}

/// Splits the array into a slice of `D`-element arrays, starting at the
/// beginning of the array, and a remainder `R`-element array.
#[inline]
pub(crate) const fn array_as_chunks_mut<T, const N: usize, const D: usize, const R: usize>(
    array: &mut [T; N],
) -> (&mut [[T; D]], &mut [T; R]) {
    const { assert!(N % D == R) };
    let (init, tail) = array_rsplit_array_mut(array);
    let (chunks, []) = init.as_chunks_mut() else {
        unreachable!()
    };
    (chunks, tail)
}

/// Divides one array reference into two at an index from the end.
///
/// This functions exists because `array::rsplit_array_ref` is not stable.
#[inline]
pub(crate) const fn array_rsplit_array_ref<T, const N: usize, const M: usize>(
    array: &[T; N],
) -> (&[T], &[T; M]) {
    const { assert!(M <= N) };
    let Some((init, tail)) = array.split_last_chunk() else {
        unreachable!()
    };
    (init, tail)
}

/// Divides one mutable array reference into two at an index from the end.
///
/// This functions exists because `array::rsplit_array_mut` is not stable.
#[inline]
pub(crate) const fn array_rsplit_array_mut<T, const N: usize, const M: usize>(
    array: &mut [T; N],
) -> (&mut [T], &mut [T; M]) {
    const { assert!(M <= N) };
    let Some((init, tail)) = array.split_last_chunk_mut() else {
        unreachable!()
    };
    (init, tail)
}
