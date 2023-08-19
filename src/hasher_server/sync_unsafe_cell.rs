use std::{cell::UnsafeCell, fmt::Debug};

#[repr(transparent)]
pub struct SyncUnsafeCell<T: ?Sized>(UnsafeCell<T>);

unsafe impl<T: ?Sized> Send for SyncUnsafeCell<T> {}

unsafe impl<T: ?Sized> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    pub const fn new(value: T) -> SyncUnsafeCell<T> {
        SyncUnsafeCell(UnsafeCell::new(value))
    }
}

impl<T: ?Sized> SyncUnsafeCell<T> {
    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}

impl<T> Debug for SyncUnsafeCell<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
