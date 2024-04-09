//! Scalar pattern scanning backend

use crate::pattern::Pattern;
use crate::ScanResult;

/// Find the first occurrence of a pattern in the binary
/// using scalar instructions
///
/// # Safety
///
/// * `binary` - is a valid pointer
///
/// * `binary_size` - corresponds to a valid size of `binary`
pub unsafe fn find(pattern: &Pattern, binary: *const u8, binary_size: usize) -> ScanResult {
    // SAFETY: safe to call as the pointer will be exactly one byte past the end of the binary
    let binary_end = unsafe { binary.add(binary_size) };

    for binary_offset in 0..binary_size {
        let mut found = true;

        for pattern_offset in 0..pattern.data.len() {
            if pattern.mask[pattern_offset] == 0x00 {
                continue;
            }

            // SAFETY: safe to call as further behavior doesn't rely on overflows
            // further reads from this address are safe because of the min call
            // ensuring the pointer is always in bounds
            let checked_addr = unsafe {
                binary
                    .add(binary_offset)
                    .add(pattern_offset)
                    .min(binary_end)
            };

            // SAFETY: checked addr is always in binary bounds
            if unsafe { checked_addr.read_volatile() } != pattern.data[pattern_offset] {
                found = false;
                break;
            }
        }

        if found {
            // SAFETY: safe to call because binary offset never gets out of binary+binary_size space
            let addr = unsafe { binary.add(binary_offset) };
            return ScanResult { addr };
        }
    }
    ScanResult {
        addr: core::ptr::null(),
    }
}
