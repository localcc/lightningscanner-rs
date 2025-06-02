//! IDA-style pattern

use crate::aligned_bytes::AlignedBytes;

/// An IDA-style binary pattern
pub struct Pattern {
    pub(crate) data: Box<AlignedBytes<32>>,
    pub(crate) mask: Box<AlignedBytes<32>>,
    pub(crate) unpadded_size: usize,
}

impl Pattern {
    const ALIGNMENT: usize = 32;

    /// Create a new IDA-style [`Pattern`] instance
    ///
    /// # Example
    ///
    /// ```
    /// use lightningscanner::pattern::Pattern;
    ///
    /// Pattern::new("48 89 5c 24 ?? 48 89 6c");
    /// ```
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.chars().collect::<Vec<_>>();

        let mut data = Vec::new();
        let mut mask = Vec::new();

        let mut i = 0;
        while i < pattern.len() {
            let symbol = pattern[i];
            let next_symbol = pattern.get(i + 1).copied().unwrap_or('\0');

            i += 1;

            match symbol {
                ' ' => continue,
                '?' => {
                    data.push(0x00);
                    mask.push(0x00);

                    if next_symbol == '?' {
                        i += 1;
                    }

                    continue;
                }
                _ => {
                    let byte = Self::char_to_byte(symbol) << 4 | Self::char_to_byte(next_symbol);

                    data.push(byte);
                    mask.push(0xff);

                    i += 1;
                }
            }

            if symbol == ' ' {
                continue;
            }
        }

        let unpadded_size = data.len();

        let count = f32::ceil(unpadded_size as f32 / Self::ALIGNMENT as f32) as usize;
        let padding_size = count * Self::ALIGNMENT - unpadded_size;

        data.resize(unpadded_size + padding_size, 0);
        mask.resize(unpadded_size + padding_size, 0);

        Pattern {
            data: AlignedBytes::new(&data),
            mask: AlignedBytes::new(&mask),
            unpadded_size,
        }
    }

    /// Create a new [`Pattern`] instance based upon a string literal.
    /// 
    /// # Example
    /// 
    /// ```
    /// use lightningscanner::pattern::Pattern;
    /// 
    /// Pattern::new_string("LocalPlayer")
    /// ```
    pub fn new_string(string: &str) -> Self {
        let bytes = string.as_bytes();
        
        let mut data = bytes.to_vec();
        let mut mask = vec![0xff; bytes.len()];
        
        let unpadded_size = data.len();
        
        let count = f32::ceil(unpadded_size as f32 / Self::ALIGNMENT as f32) as usize;
        let padding_size = count * Self::ALIGNMENT - unpadded_size;
        
        data.resize(unpadded_size + padding_size, 0);
        mask.resize(unpadded_size + padding_size, 0);
        
        Pattern {
            data: AlignedBytes::new(&data),
            mask: AlignedBytes::new(&mask),
            unpadded_size,
        }
    }

    const fn char_to_byte(c: char) -> u8 {
        if c >= 'a' && c <= 'z' {
            c as u8 - b'a' + 0xA
        } else if c >= 'A' && c <= 'Z' {
            c as u8 - b'A' + 0xA
        } else if c >= '0' && c <= '9' {
            c as u8 - b'0'
        } else {
            0
        }
    }
}

impl From<&str> for Pattern {
    fn from(value: &str) -> Self {
        Pattern::new(value)
    }
}
