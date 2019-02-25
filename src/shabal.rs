use block_buffer::block_padding::Iso7816;
use block_buffer::byteorder::{ByteOrder, LE};
use block_buffer::BlockBuffer;
use digest::generic_array::typenum::{U24, U28, U32, U48, U64};
use digest::generic_array::GenericArray;
pub use digest::{impl_write, Digest};
use digest::{BlockInput, FixedOutput, Input, Reset};
use opaque_debug::impl_opaque_debug;

use consts::{
    A_INIT_192, A_INIT_224, A_INIT_256, A_INIT_384, A_INIT_512, B_INIT_192, B_INIT_224, B_INIT_256,
    B_INIT_384, B_INIT_512, C_INIT_192, C_INIT_224, C_INIT_256, C_INIT_384, C_INIT_512,
};

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

/// A structure that represents that state of a digest computation for the
/// Sabal 512 family of digest functions
#[derive(Clone)]
struct Engine256State {
    a: [u32; 12],
    b: [u32; 16],
    c: [u32; 16],
    whigh: u32,
    wlow: u32,
}

impl Engine256State {
    fn new(a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) -> Self {
        Self {
            a: *a,
            b: *b,
            c: *c,
            wlow: 1,
            whigh: 0,
        }
    }

    pub fn process_block(&mut self, block: &Block) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        compress(self, block);
    }

    pub fn process_final_block(&mut self, block: &Block) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 64]) };
        compress_final(self, block);
    }
}

/// A structure that keeps track of the state of the Shabal-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone)]
struct Engine256 {
    buffer: BlockBuffer<BlockSize>,
    state: Engine256State,
}

impl Engine256 {
    fn new(a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) -> Engine256 {
        Engine256 {
            buffer: Default::default(),
            state: Engine256State::new(a, b, c),
        }
    }

    fn input(&mut self, input: &[u8]) {
        let state = &mut self.state;
        self.buffer.input(input, |input| state.process_block(input));
    }

    fn finish(&mut self) {
        let state = &mut self.state;
        let block = self.buffer.pad_with::<Iso7816>().unwrap();
        state.process_final_block(block);
    }

    fn reset(&mut self, a: &[u32; 12], b: &[u32; 16], c: &[u32; 16]) {
        self.state = Engine256State::new(a, b, c);
        self.buffer.reset();
    }
}

/// The Shabal-256 hash algorithm with the Shabal-512 initial hash value.
#[derive(Clone)]
pub struct Shabal512 {
    engine: Engine256,
}

impl Default for Shabal512 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_512, &B_INIT_512, &C_INIT_512),
        }
    }
}

impl BlockInput for Shabal512 {
    type BlockSize = BlockSize;
}

impl Input for Shabal512 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal512 {
    type OutputSize = U64;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[0..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal512 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_512, &B_INIT_512, &C_INIT_512);
    }
}

/// The Shabal-256 hash algorithm with the Shabal-384 initial hash value.
#[derive(Clone)]
pub struct Shabal384 {
    engine: Engine256,
}

impl Default for Shabal384 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_384, &B_INIT_384, &C_INIT_384),
        }
    }
}

impl BlockInput for Shabal384 {
    type BlockSize = BlockSize;
}

impl Input for Shabal384 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal384 {
    type OutputSize = U48;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[4..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal384 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_384, &B_INIT_384, &C_INIT_384);
    }
}

/// The Shabal-256 hash algorithm with the Shabal-256 initial hash value.
#[derive(Clone)]
pub struct Shabal256 {
    engine: Engine256,
}

impl Default for Shabal256 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_256, &B_INIT_256, &C_INIT_256),
        }
    }
}

impl BlockInput for Shabal256 {
    type BlockSize = BlockSize;
}

impl Input for Shabal256 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal256 {
    type OutputSize = U32;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[8..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal256 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_256, &B_INIT_256, &C_INIT_256);
    }
}

/// The Shabal-256 hash algorithm with the Shabal-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone)]
pub struct Shabal224 {
    engine: Engine256,
}

impl Default for Shabal224 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_224, &B_INIT_224, &C_INIT_224),
        }
    }
}

impl BlockInput for Shabal224 {
    type BlockSize = BlockSize;
}

impl Input for Shabal224 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal224 {
    type OutputSize = U28;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[9..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal224 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_224, &B_INIT_224, &C_INIT_224);
    }
}

/// The Shabal-256 hash algorithm with the Shabal-192 initial hash value. The result
/// is truncated to 192 bits.
#[derive(Clone)]
pub struct Shabal192 {
    engine: Engine256,
}

impl Default for Shabal192 {
    fn default() -> Self {
        Self {
            engine: Engine256::new(&A_INIT_192, &B_INIT_192, &C_INIT_192),
        }
    }
}

impl BlockInput for Shabal192 {
    type BlockSize = BlockSize;
}

impl Input for Shabal192 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        self.engine.input(input.as_ref());
    }
}

impl FixedOutput for Shabal192 {
    type OutputSize = U24;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        LE::write_u32_into(&self.engine.state.b[10..16], out.as_mut_slice());
        out
    }
}

impl Reset for Shabal192 {
    fn reset(&mut self) {
        self.engine.reset(&A_INIT_192, &B_INIT_192, &C_INIT_192);
    }
}

impl_opaque_debug!(Shabal512);
impl_opaque_debug!(Shabal384);
impl_opaque_debug!(Shabal256);
impl_opaque_debug!(Shabal224);
impl_opaque_debug!(Shabal192);

impl_write!(Shabal512);
impl_write!(Shabal384);
impl_write!(Shabal256);
impl_write!(Shabal224);
impl_write!(Shabal192);

trait ModuloSignedExt {
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

fn compress(state: &mut Engine256State, input: &[u8; 64]) {
    let a = &mut state.a;
    let b = &mut state.b;
    let c = &mut state.c;

    let mut m = [0; 16];
    LE::read_u32_into(input, &mut m);

    for i in 0..b.len() {
        b[i] = b[i].wrapping_add(m[i]);
    }

    a[0] ^= state.wlow;
    a[1] ^= state.whigh;

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

fn compress_final(state: &mut Engine256State, input: &[u8; 64]) {
    let a = &mut state.a;
    let b = &mut state.b;
    let c = &mut state.c;

    let mut m = [0; 16];
    LE::read_u32_into(input, &mut m);

    for i in 0..b.len() {
        b[i] = b[i].wrapping_add(m[i]);
    }

    a[0] ^= state.wlow;
    a[1] ^= state.whigh;

    perm(a, b, c, &mut m);

    for _ in 0..3 {
        core::mem::swap(b, c);
        a[0] ^= state.wlow;
        a[1] ^= state.whigh;
        perm(a, b, c, &mut m);
    }
}

#[inline(always)]
fn perm(a: &mut [u32; 12], b: &mut [u32; 16], c: &mut [u32; 16], m: &mut [u32; 16]) {
    for b in b.iter_mut() {
        *b = b.wrapping_shl(17) | b.wrapping_shr(15);
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
