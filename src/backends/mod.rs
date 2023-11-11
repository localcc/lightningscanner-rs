//! Pattern scanning backends

use crate::pattern::Pattern;
use crate::{ScanMode, ScanResult};

#[cfg(target_arch = "x86_64")]
mod avx2;
mod scalar;
#[cfg(target_arch = "x86_64")]
mod sse42;

/// Find the first occurrence of a pattern in the binary
///
/// # Safety
///
/// * `binary` - is a valid pointer
/// * `binary_size` - corresponds to a valid size of `binary`
pub unsafe fn find(
    pattern: &Pattern,
    preferred_scan_mode: Option<ScanMode>,
    binary: *const u8,
    binary_size: usize,
) -> ScanResult {
    #[cfg(target_arch = "x86_64")]
    {
        let avx2 = is_x86_feature_detected!("avx2");
        let sse42 = is_x86_feature_detected!("sse4.2");

        match (preferred_scan_mode, avx2, sse42) {
            (Some(ScanMode::Avx2) | None, true, _) => {
                // SAFETY: safe to call as long as the safety conditions were met for this function
                return unsafe { avx2::find(pattern, binary, binary_size) };
            }
            (Some(ScanMode::Sse42), _, true) | (None, false, true) => {
                // SAFETY: safe to call as long as the safety conditions were met for this function
                return unsafe { sse42::find(pattern, binary, binary_size) };
            }
            _ => {}
        }
    }

    // SAFETY: safe to call as long as the safety conditions were met for this function
    unsafe { scalar::find(pattern, binary, binary_size) }
}
