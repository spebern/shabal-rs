#![no_std]
extern crate digest;
extern crate shabal;

use digest::dev::one_million_a;

#[test]
fn sha192_1million_a() {
    let output = include_bytes!("data/shabal192_one_million_a.bin");
    one_million_a::<shabal::Shabal192>(output);
}

#[test]
fn sha224_1million_a() {
    let output = include_bytes!("data/shabal224_one_million_a.bin");
    one_million_a::<shabal::Shabal224>(output);
}

#[test]
fn sha256_1million_a() {
    let output = include_bytes!("data/shabal256_one_million_a.bin");
    one_million_a::<shabal::Shabal256>(output);
}

#[test]
fn sha384_1million_a() {
    let output = include_bytes!("data/shabal384_one_million_a.bin");
    one_million_a::<shabal::Shabal384>(output);
}

#[test]
fn sha512_1million_a() {
    let output = include_bytes!("data/shabal512_one_million_a.bin");
    one_million_a::<shabal::Shabal512>(output);
}
