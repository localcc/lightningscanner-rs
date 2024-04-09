//! Aligned byte storage implementation

extern crate alloc;

use core::ops::Deref;

use alloc::boxed::Box;
use elain::{Align, Alignment};

#[repr(C)]
pub struct AlignedBytes<const N: usize>(Align<N>, [u8])
where
    Align<N>: Alignment;

#[repr(C)]
struct AlignedByte<const N: usize>(Align<N>, u8)
where
    Align<N>: Alignment;

impl<const N: usize> AlignedBytes<N>
where
    Align<N>: Alignment,
{
    /// Create a new `AlignedBytes` instance from a slice
    pub fn new(data: &[u8]) -> Box<AlignedBytes<N>> {
        if data.is_empty() {
            // SAFETY: The pointer isn't null and is aligned because it was returned from
            // `NonNull::dangling`. The length is zero, so no other requirements apply.
            unsafe {
                Self::from_byte_ptr(
                    core::ptr::NonNull::<AlignedByte<N>>::dangling()
                        .as_ptr()
                        .cast::<u8>(),
                    0,
                )
            }
        } else {
            if data.len().checked_next_multiple_of(N).unwrap_or(usize::MAX) > isize::MAX as usize {
                panic!("unable to allocate {} bytes (overflows isize)", data.len());
            }

            // SAFETY: The alignment `N` is not zero and is a power of two. `data.len()`'s next
            // multiple of N does not overflow an `isize`.
            let layout = unsafe { alloc::alloc::Layout::from_size_align_unchecked(data.len(), N) };

            // SAFETY: `layout`'s size is not zero.
            let ptr = unsafe { alloc::alloc::alloc(layout) };

            if ptr.is_null() {
                alloc::alloc::handle_alloc_error(layout)
            } else {
                // SAFETY: `data.as_ptr()` is valid for reads because it comes from a slice. `ptr` is
                // valid for writes because it was returned from `alloc::alloc` and is not null. They
                // can't overlap because `data` has a lifetime longer than this function and `ptr` was
                // just allocated in this function.
                unsafe {
                    core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                }

                // SAFETY: `ptr` is non-null, and is aligned because it was returned from `alloc::alloc`.
                // The data pointed to is valid for reads and writes because it was initialized by
                // `ptr::copy_nonoverlapping`. `ptr` is currently allocated by the global allocator.
                unsafe { Self::from_byte_ptr(ptr, data.len()) }
            }
        }
    }

    /// # Safety
    ///
    /// `ptr` must be non-null, aligned to N bytes, and valid for reads and writes for `len` bytes.
    /// The data pointed to must be initialized. If `len` is non-zero, `ptr` must be currently
    /// allocated by the global allocator and valid to deallocate.
    unsafe fn from_byte_ptr(ptr: *mut u8, len: usize) -> Box<AlignedBytes<N>> {
        let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);

        // SAFETY: The invariants of `Box::from_raw` are enforced by this function's safety
        // contract.
        unsafe { Box::from_raw(slice_ptr as *mut AlignedBytes<N>) }
    }
}

impl<const N: usize> Deref for AlignedBytes<N>
where
    Align<N>: Alignment,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}
