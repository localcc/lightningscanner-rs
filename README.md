# LightningScanner

A lightning-fast memory pattern scanner, capable of scanning gigabytes of data per second.

## Installation

```
cargo add lightningscanner
```

## Examples

Here's an example of how to find an IDA-style memory pattern inside of a binary.

```rust

use lightningscanner::Scanner;

fn main() {
    let binary = [0xab, 0xec, 0x48, 0x89, 0x5c, 0x24, 0xee, 0x48, 0x89, 0x6c];

    let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c");
    let result = unsafe { scanner.find(None, binary.as_ptr(), binary.len()) };

    println!("{:?}", result);
}

```
