const W: usize = 32;
const N: usize = 624;
const M: usize = 397;
const R: usize = 31;

const U: usize = 11;
const S: usize = 7;
const T: usize = 15;
const L: usize = 18;

const A: u32 = 0x9908b0df;
const D: u32 = 0xffffffff;
const B: u32 = 0x9d2c5680;
const C: u32 = 0xefc60000;
const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1u32 << R) - 1;
const UPPER_MASK: u32 = LOWER_MASK ^ 0xffffffff;

const DEFAULT_SEED: u32 = 5489;

#[derive(Clone)]
pub struct MT19937 {
    mt: [u32; N],
    index: usize,
}

impl MT19937 {
    pub fn from_state(mt: &[u32], idx: usize) -> Self {
        assert!(mt.len() == N);
        let mut m = [0u32; N];
        for (i,x) in mt.iter().enumerate() { m[i] = *x; }
        return Self {
            mt: m,
            index: idx
        };
    }

    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; N];
        mt[0] = seed;
        for i in 1..N {
            mt[i] = F.wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> (W - 2)));
            mt[i] = mt[i].wrapping_add(i as u32);
        }
        return Self { mt: mt, index: N };
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_SEED)
    }

    pub fn get_next(&mut self) -> u32 {
        assert!(self.index <= N);
        if self.index == N {
            self.twist();
        }

        // "temper"
        let mut y = self.mt[self.index];
        //y ^= (y >> U) & D;
        //y ^= (y << S) & B;
        //y ^= (y << T) & C;
        //y ^= y >> L;
        y = right_and(U, D, y);
        y = left_and(S, B, y);
        y = left_and(T, C, y);
        y = right_and(L, 0xffffffff, y);

        self.index += 1;
        return y;
    }


    fn twist(&mut self) {
        for i in 0..N {
            let x =
                (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }
}

pub fn untemper(mut y: u32) -> u32 {
    y = invert_right_and(L, 0xffffffff, y);
    y = invert_left_and(T, C, y);
    y = invert_left_and(S, B, y);
    y = invert_right_and(U, D, y);
    return y;
}

impl Iterator for MT19937 {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        Some(self.get_next())
    }
}

/// Perform y ^ ((y << s) & a)
fn left_and(s: usize, a: u32, y: u32) -> u32 {
    y ^ ( (y<<s) & a )
}

/// Perform y ^ ((y >> s) & a)
fn right_and(s: usize, a: u32, y: u32) -> u32 {
    y ^ ( (y>>s) & a )
}

/// Return all 0 except lsb which will be bit i of w
fn get_bit(w: u32, i: usize) -> u8 {
    ((w << (31-i)) >> 31) as u8
}

/// Return w with bit i set to b
fn set_bit(w: u32, i: usize, b: u8) -> u32 {
    let one = 1 << i;
    if b == 0 {
        w & (!one)
    } else {
        w | one
    }
}

/// Invert y ^ ((y << s) & a)
fn invert_left_and(s: usize, a: u32, yp: u32) -> u32 {
    // Bottom s bits are same as yp:
    let sinv = 32 - s;
    let mut yb = (yp << sinv) >> sinv;

    // Do rest one bit at a time
    // yb[i] = yp[i] ^ (y[i-s] & a[i])
    // So as long as we go from low idx to high idx, yb[i-s] will
    // already be y[i-s].
    for i in s..32 {
        let b = get_bit(yp, i) ^ (get_bit(yb, i-s) & get_bit(a, i));
        yb = set_bit(yb, i, b);
    }
    return yb;
}

/// Invert y ^ ((y >> s) & a)
fn invert_right_and(s: usize, a: u32, yp: u32) -> u32 {
    // Top s bits are same as yp:
    let sinv = 32 - s;
    let mut yb = (yp >> sinv) << sinv;

    // Do rest one bit at a time
    // yb[i] = yp[i] ^ (y[i+s] & a[i])
    // So as long as we go from high idx to low idx, yb[i0s] will
    // already be y[i+s].
    for i in (0..sinv).rev() {
        let b = get_bit(yp, i) ^ (get_bit(yb, i+s) & get_bit(a, i));
        yb = set_bit(yb, i, b);
    }
    return yb;
}

// From oeis.org
#[allow(dead_code)]
const TEST_VEC: &'static [u32] = &[
    3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391,
    3922919429, 949333985, 2715962298, 1323567403, 418932835, 2350294565,
    1196140740, 809094426, 2348838239, 4264392720, 4112460519, 4279768804,
    4144164697, 4156218106, 676943009, 3117454609,
];

#[test]
fn test_default() {
    let result: Vec<_> = MT19937::default().take(TEST_VEC.len()).collect();
    assert!(result == TEST_VEC);
}
