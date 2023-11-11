use lightningscanner::{ScanMode, Scanner};

const PATTERN: &str = "40 57 48 83 EC ? 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 49 8B E9 48 8B F2";

const DATA_SET: [u8; 72] = [
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x28, 0xFE, 0xFF, 0xFF, 0xFF, 0x48,
    0x89, 0x5C, 0x24, 0x40, 0x48, 0x89, 0x6C, 0x24, 0x48, 0x48, 0x89, 0x74, 0x24, 0x50, 0x49, 0x8B,
    0xE9, 0x49, 0x8B, 0xF0, 0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x28, 0xFE,
    0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x40, 0x48, 0x89, 0x6C, 0x24, 0x48, 0x48, 0x89, 0x74,
    0x24, 0x50, 0x49, 0x8B, 0xE9, 0x48, 0x8B, 0xF2,
];

#[test]
#[cfg(target_feature = "avx2")]
fn avx2() {
    let scanner = Scanner::new(PATTERN);
    let result = scanner.find(Some(ScanMode::Avx2), &DATA_SET);

    let data_set_addr = DATA_SET.as_ptr() as usize;
    let ptr = result.get_addr() as usize;

    assert_eq!(ptr - data_set_addr, 0x24);
}

#[test]
#[cfg(target_feature = "sse4.2")]
fn sse42() {
    let scanner = Scanner::new(PATTERN);
    let result = scanner.find(Some(ScanMode::Sse42), &DATA_SET);

    let data_set_addr = DATA_SET.as_ptr() as usize;
    let ptr = result.get_addr() as usize;

    assert_eq!(ptr - data_set_addr, 0x24);
}

#[test]
fn scalar() {
    let scanner = Scanner::new(PATTERN);
    let result = scanner.find(Some(ScanMode::Scalar), &DATA_SET);

    let data_set_addr = DATA_SET.as_ptr() as usize;
    let ptr = result.get_addr() as usize;

    assert_eq!(ptr - data_set_addr, 0x24);
}
