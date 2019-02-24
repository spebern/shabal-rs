//! An implementation of the [Shabal256][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate shabal_rs;
//! # fn main() {
//! use shabal_rs::{Shabal256, Digest};
//!
//! // create a Shabal256 hasher instance
//! let mut hasher = Shabal256::new();
//!
//! // process input message
//! hasher.input(b"helloworld");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

use block_buffer::byteorder::{ByteOrder, LE};
use block_buffer::BlockBuffer;
use digest::generic_array::typenum::{U32, U64};
use digest::generic_array::GenericArray;
pub use digest::{impl_write, Digest};
use digest::{BlockInput, FixedOutput, Input, Reset};
use opaque_debug::impl_opaque_debug;

mod consts;

/// The Shabal256 hasher
#[derive(Clone)]
pub struct Shabal256 {
    buffer: BlockBuffer<U64>,
    state: State,
}

#[derive(Clone)]
struct State {
    a: [u32; 12],
    b: [u32; 16],
    c: [u32; 16],
    whigh: u32,
    wlow: u32,
}

impl Default for State {
    fn default() -> Self {
        Self {
            a: consts::A_INIT,
            b: consts::B_INIT,
            c: consts::C_INIT,
            wlow: 1,
            whigh: 0,
        }
    }
}

impl Default for Shabal256 {
    fn default() -> Self {
        Self {
            buffer: Default::default(),
            state: State::default(),
        }
    }
}

#[inline(always)]
fn convert(d: &GenericArray<u8, U64>) -> &[u8; 64] {
    unsafe { &*(d.as_ptr() as *const [u8; 64]) }
}

impl Shabal256 {
    #[inline]
    fn finalize(&mut self) {
        let state = &mut self.state;
        self.buffer
            .len64_padding::<LE, _>(0, |d| compress_final(state, convert(d)));
    }
}

impl BlockInput for Shabal256 {
    type BlockSize = U64;
}

impl Input for Shabal256 {
    #[inline]
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        let self_state = &mut self.state;
        self.buffer
            .input(input, |d| compress(self_state, convert(d)));
    }
}

impl FixedOutput for Shabal256 {
    type OutputSize = U32;

    #[inline]
    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        self.finalize();
        LE::write_u32_into(&self.state.b[8..16], &mut out);
        out
    }
}

impl Reset for Shabal256 {
    fn reset(&mut self) {
        self.state = State::default();
        self.buffer.reset();
    }
}

pub trait ModuloSignedExt {
    fn modulo(&self, n: Self) -> Self;
}
macro_rules! modulo_signed_ext_impl {
    ($($t:ty)*) => ($(
        impl ModuloSignedExt for $t {
            #[inline(always)]
            fn modulo(&self, n: Self) -> Self {
                (self % n + n) % n
            }
        }
    )*)
}
modulo_signed_ext_impl! { isize }

fn compress(state: &mut State, input: &[u8; 64]) {
    let a = &mut state.a;
    let b = &mut state.b;
    let c = &mut state.c;

    let mut m = [0; 16];
    LE::read_u32_into(input, &mut m);

    for i in 0..b.len() {
        b[i] = b[i].wrapping_add(m[i]);
    }

    a[0] = a[0] ^ state.wlow;
    a[1] = a[1] ^ state.whigh;

    perm(a, b, c, &mut m);

    for i in 0..c.len() {
        c[i] = c[i].wrapping_sub(m[i]);
    }

    core::mem::swap(b, c);

    state.wlow = state.wlow.wrapping_add(1);
    if state.wlow == 0 {
        state.whigh = state.whigh.wrapping_add(1);
    }
}

fn compress_final(state: &mut State, input: &[u8; 64]) {
    let a = &mut state.a;
    let b = &mut state.b;
    let c = &mut state.c;

    let mut m = [0; 16];
    LE::read_u32_into(input, &mut m);

    for i in 0..b.len() {
        b[i] = b[i].wrapping_add(m[i]);
    }

    a[0] = a[0] ^ state.wlow;
    a[1] = a[1] ^ state.whigh;

    perm(a, b, c, &mut m);

    for _ in 0..3 {
        core::mem::swap(b, c);
        a[0] = a[0] ^ state.wlow;
        a[1] = a[1] ^ state.whigh;
        perm(a, b, c, &mut m);
    }
}

#[inline(always)]
fn perm(a: &mut [u32; 12], b: &mut [u32; 16], c: &mut [u32; 16], m: &mut [u32; 16]) {
    for i in 0..b.len() {
        b[i] = b[i].wrapping_shl(17) | b[i].wrapping_shr(15);
    }
    perm_block(a, 0, b, c, m);
    perm_block(a, 4, b, c, m);
    perm_block(a, 8, b, c, m);
    let c_len = c.len() as isize;
    for i in 0..12 {
        a[i as usize] = a[i as usize]
            .wrapping_add(c[(11 + i).modulo(c_len) as usize])
            .wrapping_add(c[(15 + i).modulo(c_len) as usize])
            .wrapping_add(c[(3 + i).modulo(c_len) as usize]);
    }
}

#[inline(always)]
fn perm_block(
    a: &mut [u32; 12],
    o: isize,
    b: &mut [u32; 16],
    c: &mut [u32; 16],
    m: &mut [u32; 16],
) {
    for i in 0..16 {
        let a_len = a.len() as isize;
        let b_len = b.len() as isize;
        let c_len = c.len() as isize;

        let xa0 = a[((i + o).modulo(a_len)) as usize];
        let xa1 = a[((i + o - 1).modulo(a_len)) as usize];
        let xb0 = b[i as usize];
        let xb1 = b[((13 + i).modulo(b_len)) as usize];
        let xb2 = b[((9 + i).modulo(b_len)) as usize];
        let xb3 = b[((6 + i).modulo(b_len)) as usize];
        let xc = c[((8 - i).modulo(c_len)) as usize];
        let xm = m[i as usize];

        a[((i + o).modulo(a_len)) as usize] =
            (xa0 ^ (xa1.wrapping_shl(15) | xa1.wrapping_shr(17)).wrapping_mul(5) ^ xc)
                .wrapping_mul(3)
                ^ xb1
                ^ (xb2 & !xb3)
                ^ xm;
        b[i as usize] =
            !((xb0.wrapping_shl(1) | xb0.wrapping_shr(31)) ^ a[((i + o).modulo(a_len)) as usize]);
    }
}

impl_opaque_debug!(Shabal256);
impl_write!(Shabal256);
