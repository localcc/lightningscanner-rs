//! AVX2 pattern scanning backend

use crate::pattern::Pattern;
use crate::ScanResult;
use std::arch::x86_64::{
    _mm256_blendv_epi8, _mm256_cmpeq_epi8, _mm256_load_si256, _mm256_loadu_si256,
    _mm256_movemask_epi8, _mm256_set1_epi8,
};
use std::ptr;

/// Find the first occurrence of a pattern in the binary
/// using AVX2 instructions
///
/// # Safety
///
/// * `binary` - is a valid pointer
///
/// * `binary_size` - corresponds to a valid size of `binary`
///
/// * Currently running CPU supports AVX2
#[target_feature(enable = "avx2")]
pub unsafe fn find(pattern_data: &Pattern, binary: *const u8, binary_size: usize) -> ScanResult {
    const UNIT_SIZE: usize = 32;

    let mut processed_size = 0;

    // SAFETY: this function is only called if the CPU supports AVX2
    unsafe {
        let mut pattern = _mm256_load_si256(pattern_data.data.as_ptr() as *const _);
        let mut mask = _mm256_load_si256(pattern_data.mask.as_ptr() as *const _);
        let all_zeros = _mm256_set1_epi8(0x00);

        let mut chunk = 0;
        while chunk < binary_size {
            let chunk_data = _mm256_loadu_si256(binary.add(chunk) as *const _);

            let blend = _mm256_blendv_epi8(all_zeros, chunk_data, mask);
            let eq = _mm256_cmpeq_epi8(pattern, blend);

            if _mm256_movemask_epi8(eq) as u32 == 0xffffffff {
                processed_size += UNIT_SIZE;

                if processed_size < pattern_data.unpadded_size {
                    chunk += UNIT_SIZE - 1;

                    pattern = _mm256_load_si256(
                        pattern_data.data.as_ptr().add(processed_size) as *const _
                    );
                    mask = _mm256_load_si256(
                        pattern_data.mask.as_ptr().add(processed_size) as *const _
                    );
                } else {
                    let addr = binary.add(chunk).sub(processed_size).add(UNIT_SIZE);
                    return ScanResult { addr };
                }
            } else {
                pattern = _mm256_load_si256(pattern_data.data.as_ptr() as *const _);
                mask = _mm256_load_si256(pattern_data.mask.as_ptr() as *const _);
                processed_size = 0;
            }
            chunk += 1;
        }
    }

    ScanResult { addr: ptr::null() }
}
