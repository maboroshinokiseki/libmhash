use std::slice;

#[inline(always)]
pub(super) fn slice_as_chunks<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    debug_assert_eq!(slice.len() % N, 0);
    unsafe { slice::from_raw_parts(slice.as_ptr().cast(), slice.len() / N) }
}

#[inline(always)]
pub(super) fn slice_as_chunks_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    debug_assert_eq!(slice.len() % N, 0);
    unsafe { slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len() / N) }
}
