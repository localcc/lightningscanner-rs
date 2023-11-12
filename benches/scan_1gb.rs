use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use lightningscanner::{ScanMode, Scanner};
use tinyrand::{Rand, Wyrand};

fn benchmark(c: &mut Criterion) {
    const GB: usize = 1073741824;

    let mut data = Vec::with_capacity(GB);
    let mut rand = Wyrand::default();
    for _ in 0..(GB / 2) {
        let value = rand.next_u16();
        data.push((value & 0xff) as u8);
        data.push(((value >> 8) & 0xff) as u8);
    }

    const PATTERN_DATA: [u8; 32] = [
        0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x48, 0x89, 0x74, 0x24, 0x00,
        0x48, 0x89, 0x7C, 0x24, 0x00, 0x41, 0x56, 0x41, 0x57, 0x4c, 0x8b, 0x79, 0x38, 0xaa, 0xbf,
        0xcd, 0x00,
    ];

    let len = data.len();
    data[len - 32..].copy_from_slice(&PATTERN_DATA);

    let mut group = c.benchmark_group("1gb scan");
    group.throughput(Throughput::Bytes(GB as u64));

    group.bench_function("scalar", |b| {
        let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 48 89 7c 24 ?? 41 56 41 57 4c 8b 79 38 aa bf cd");
        b.iter(|| {
            // SAFETY: data is a valid slice
            unsafe { scanner.find(Some(ScanMode::Scalar), data.as_ptr(), data.len()) }
        });
    });

    group.bench_function("sse4.2", |b| {
        let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 48 89 7c 24 ?? 41 56 41 57 4c 8b 79 38 aa bf cd");
        b.iter(|| {
            // SAFETY: data is a valid slice
            unsafe { scanner.find(Some(ScanMode::Sse42), data.as_ptr(), data.len()) }
        });
    });

    group.bench_function("avx2", |b| {
        let scanner = Scanner::new("48 89 5c 24 ?? 48 89 6c 24 ?? 48 89 74 24 ?? 48 89 7c 24 ?? 41 56 41 57 4c 8b 79 38 aa bf cd");
        b.iter(|| {
            // SAFETY: data is a valid slice
            unsafe { scanner.find(Some(ScanMode::Avx2), data.as_ptr(), data.len()) }
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
