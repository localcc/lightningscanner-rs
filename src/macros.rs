/// Create a new [`Pattern`] instance from a pattern string literal at compile time.
///
/// The macro parses the pattern at compile time, which avoids the runtime cost of parsing.
/// The resulting `Pattern` can be used to create a [`Scanner`].
///
/// # Example
///
/// ```no_run
/// use lightningscanner::{create_pattern, Scanner};
///
/// // The pattern is parsed at compile-time.
/// let pattern = create_pattern!("a0 9e 87 00 ?? 5c");
///
/// // You can then create a scanner from it.
/// let scanner = Scanner::from(pattern);
/// ```
#[macro_export]
macro_rules! create_pattern {
    ($pattern:expr) => {{
        // This module contains the compile-time parser for IDA-style patterns.
        // It's defined inside the macro to not pollute the module namespace.
        // All functions inside are `const` and will be evaluated at compile time.
        mod const_parser {
            // A struct to hold the result of the compile-time parsing.
            // The arrays have a fixed size, and `len` holds the actual pattern length.
            // This is a common pattern for `const` contexts where dynamic allocation is not possible.
            pub struct ParsedPattern {
                pub data: [u8; 256],
                pub mask: [u8; 256],
                pub len: usize,
            }

            // A `const` version of `char_to_byte` from the original `Pattern::new`.
            const fn char_to_byte(c: u8) -> u8 {
                if c >= b'a' && c <= b'z' {
                    c - b'a' + 0xA
                } else if c >= b'A' && c <= b'Z' {
                    c - b'A' + 0xA
                } else if c >= b'0' && c <= b'9' {
                    c - b'0'
                } else {
                    0
                }
            }

            // The main `const` function to parse the pattern string.
            pub const fn parse_pattern(pattern: &str) -> ParsedPattern {
                let pattern = pattern.as_bytes();
                let mut data = [0u8; 256];
                let mut mask = [0u8; 256];
                let mut len = 0;
                let mut i = 0;

                while i < pattern.len() {
                    // We use a fixed-size array, so we must check for overflow.
                    if len >= 256 {
                        panic!("Pattern is too long for compile-time parsing (max 256 bytes)");
                    }

                    let symbol = pattern[i];
                    let next_symbol = if i + 1 < pattern.len() {
                        pattern[i + 1]
                    } else {
                        b'\0'
                    };

                    i += 1;

                    match symbol {
                        b' ' => continue,
                        b'?' => {
                            data[len] = 0x00;
                            mask[len] = 0x00;
                            len += 1;

                            if next_symbol == b'?' {
                                i += 1;
                            }
                            continue;
                        }
                        _ => {
                            let byte = (char_to_byte(symbol) << 4) | char_to_byte(next_symbol);
                            data[len] = byte;
                            mask[len] = 0xff;
                            len += 1;
                            i += 1;
                        }
                    }
                }

                ParsedPattern { data, mask, len }
            }
        }

        // The pattern string is parsed at compile time here.
        const PARSED: const_parser::ParsedPattern = const_parser::parse_pattern($pattern);

        // The rest of the code constructs the `Pattern` at runtime,
        // but from the data that was prepared at compile time.
        // This is necessary because `Pattern` uses heap allocation.

        let unpadded_size = PARSED.len;

        let mut data_vec = PARSED.data[..unpadded_size].to_vec();
        let mut mask_vec = PARSED.mask[..unpadded_size].to_vec();

        // The padding logic from the original `Pattern::new`.
        // We use integer arithmetic to be compatible with `const` contexts if needed,
        // although here it runs at runtime.
        const ALIGNMENT: usize = 32;
        let count = (unpadded_size + ALIGNMENT - 1) / ALIGNMENT;
        let padding_size = count * ALIGNMENT - unpadded_size;

        data_vec.resize(unpadded_size + padding_size, 0);
        mask_vec.resize(unpadded_size + padding_size, 0);

        // Finally, create the `Pattern` instance using the public constructor.
        $crate::pattern::Pattern::from_parts(
            $crate::aligned_bytes::AlignedBytes::new(&data_vec),
            $crate::aligned_bytes::AlignedBytes::new(&mask_vec),
            unpadded_size,
        )
    }};
}
