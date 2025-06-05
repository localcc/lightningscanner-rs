//! LightningScanner
//!
//! A lightning-fast memory pattern scanner, capable of scanning gigabytes of data per second.
//!
//! # Example
//!
//! ```
//! use lightningscanner::Scanner;
//!
//! let binary = [0xab, 0xec, 0x48, 0x89, 0x5c, 0x24, 0xee, 0x48, 0x89, 0x6c];
//!
//! let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c");
//! let result = unsafe { scanner.find(None, binary.as_ptr(), binary.len()) };
//!
//! println!("{:?}", result);
//! ```
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]

use crate::pattern::Pattern;

mod aligned_bytes;
mod backends;
pub mod pattern;

/// Single result IDA-style pattern scanner
///
/// A pattern scanner that searches for an IDA-style pattern
/// and returns the pointer to the first occurrence in the binary.
pub struct Scanner(Pattern);

impl Scanner {
    /// Create a new [`Scanner`] instance
    ///
    /// # Example
    ///
    /// ```
    /// use lightningscanner::Scanner;
    ///
    /// let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c");
    /// ```
    pub fn new(pattern: &str) -> Self {
        Scanner(Pattern::new(pattern))
    }

    /// Create a new [`Scanner`] instance, using a string literal pattern.
    /// 
    /// # Example
    /// 
    /// ```
    /// use lightningscanner::Scanner;
    /// 
    /// let scanner = Scanner::new_from_str("LocalPlayer");
    /// ```
    pub fn new_from_str(pattern: &str) -> Self {
        Scanner(Pattern::new_string(pattern))
    }

    /// Find the first occurence of the pattern in the binary
    ///
    /// # Params
    ///
    /// * `preferred_scan_mode` - preferred scan mode to use (Avx2, Sse42, Scalar)
    ///     if the preferred mode is not available, will choose the fastest out of the availble ones
    ///
    /// * `binary_ptr` - pointer to the first element of the binary to search the pattern in
    ///
    /// * `binary_size` - binary size
    ///
    /// # Safety
    ///
    /// * `binary_ptr` - is a valid pointer
    ///
    /// * `binary_size` - corresponds to a valid size of `binary`
    ///
    /// # Example
    ///
    /// ```
    /// use lightningscanner::Scanner;
    ///
    /// let binary = [0xab, 0xec, 0x48, 0x89, 0x5c, 0x24, 0xee, 0x48, 0x89, 0x6c];
    ///
    /// let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c");
    /// let result = unsafe { scanner.find(None, binary.as_ptr(), binary.len()) };
    ///
    /// println!("{:?}", result);
    /// ```
    pub unsafe fn find(
        &self,
        preferred_scan_mode: Option<ScanMode>,
        binary_ptr: *const u8,
        binary_size: usize,
    ) -> ScanResult {
        // SAFETY: safe to call as long as the safety conditions were met for this function
        unsafe { backends::find(&self.0, preferred_scan_mode, binary_ptr, binary_size) }
    }
}

impl From<Pattern> for Scanner {
    fn from(value: Pattern) -> Self {
        Scanner(value)
    }
}

/// Scan mode
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ScanMode {
    /// Scalar scan mode
    Scalar,
    /// Scan mode that uses SSE4.2 SIMD instructions
    Sse42,
    /// Scan mode that uses AVX2 SIMD instructions
    Avx2,
}

/// Scan result
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ScanResult {
    addr: *const u8,
}

impl ScanResult {
    /// Check if the result is a valid pointer
    pub fn is_valid(&self) -> bool {
        !self.addr.is_null()
    }

    /// Get address of this scan result
    pub fn get_addr(&self) -> *const u8 {
        self.addr
    }

    /// Get a pointer to the value
    ///
    /// Gets the result address, shifts by `offset` bytes and casts to *const T
    ///
    /// # Safety
    ///
    /// If any of the following conditions are violated, the result is Undefined
    /// Behavior:
    ///
    /// * Both the starting and resulting pointer must be either in bounds or one
    ///   byte past the end of the same [allocated object].
    ///
    /// * The computed offset, **in bytes**, cannot overflow an `isize`.
    ///
    /// * The offset being in bounds cannot rely on "wrapping around" the address
    ///   space. That is, the infinite-precision sum, **in bytes** must fit in a usize.
    ///
    /// [allocated object]: crate::ptr#allocated-object
    pub unsafe fn get_ptr<T>(&self, offset: isize) -> *const T {
        // SAFETY: the caller must uphold the safety contract for `get_ptr`.
        unsafe { self.addr.offset(offset) as *const _ }
    }

    /// Get a mutable pointer to the value
    ///
    /// Gets the result address, shifts by `offset` bytes and casts to *mut T
    ///
    /// # Safety
    ///
    /// If any of the following conditions are violated, the result is Undefined
    /// Behavior:
    ///
    /// * Both the starting and resulting pointer must be either in bounds or one
    ///   byte past the end of the same [allocated object].
    ///
    /// * The computed offset, **in bytes**, cannot overflow an `isize`.
    ///
    /// * The offset being in bounds cannot rely on "wrapping around" the address
    ///   space. That is, the infinite-precision sum, **in bytes** must fit in a usize.
    ///
    /// * The scan result was produced from an immutable reference
    ///
    /// [allocated object]: crate::ptr#allocated-object
    pub unsafe fn get_mut_ptr<T>(&self, offset: isize) -> *mut T {
        // SAFETY: the caller must uphold the safety contract for `get_mut_ptr`.
        unsafe { self.addr.offset(offset) as *mut _ }
    }
}
