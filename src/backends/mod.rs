//! Pattern scanning backends

use crate::pattern::Pattern;
use crate::ScanResult;

mod scalar;
/// Find the first occurrence of a pattern in the binary
///
/// # Safety
///
/// * `binary` - is a valid pointer
/// * `binary_size` - corresponds to a valid size of `binary`
pub unsafe fn find(pattern: &Pattern, binary: *const u8, binary_size: usize) -> ScanResult {
    unsafe { scalar::find(pattern, binary, binary_size) }
}
