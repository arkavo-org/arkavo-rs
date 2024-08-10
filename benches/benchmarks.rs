use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nanotdf::BinaryParser;

fn bench_read_kas_field(c: &mut Criterion) {
    let kas_field = vec![
        0x01, 0x0e, 0x6b, 0x61, 0x73, 0x2e, 0x76, 0x69, 0x72, 0x74, 0x72, 0x75, 0x2e, 0x63, 0x6f,
        0x6d,
    ];

    // Attempt to parse the KAS field once before benchmarking
    let mut parser = BinaryParser::new(&kas_field);
    match parser.read_kas_field() {
        Ok(_) => {
            c.bench_function("read_kas_field", |b| {
                b.iter(|| {
                    let mut parser = BinaryParser::new(black_box(&kas_field));
                    let _ = parser.read_kas_field().unwrap();
                })
            });
        }
        Err(e) => {
            panic!("Failed to read KAS field: {:?}", e);
        }
    }
}

criterion_group!(benches, bench_read_kas_field);
criterion_main!(benches);
