#![feature(test)]

extern crate test;
use nanotdf::BinaryParser;
use test::{black_box, Bencher};

#[bench]
fn bench_read_kas_field(b: &mut Bencher) {
    let kas_field = vec![
        0x01, 0x0e, 0x6b, 0x61, 0x73, 0x2e, 0x76, 0x69, 0x72, 0x74, 0x72, 0x75, 0x2e, 0x63, 0x6f,
        0x6d,
    ];

    // Attempt to parse the KAS field once before benchmarking
    let mut parser = BinaryParser::new(&kas_field);
    match parser.read_kas_field() {
        Ok(_) => {
            b.iter(|| {
                let mut parser = BinaryParser::new(black_box(&kas_field));
                let _ = parser.read_kas_field().unwrap();
            });
        }
        Err(e) => {
            panic!("Failed to read KAS field: {:?}", e);
        }
    }
}
