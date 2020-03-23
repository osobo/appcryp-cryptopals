use base64;
use hex;
use std::fs;
use std::time::SystemTime;


// == Private imports ==
mod aes_blackbox;

// == Re-exports ==
pub mod mt19937;
pub use mt19937::MT19937;
pub mod english2;
pub mod english4;
pub mod english5;
pub mod aes128;

// == Private help ==
fn purge_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

// == Short public ==
pub fn decode_hex(hexstr: &str) -> Vec<u8> {
    let hexstr = purge_ws(hexstr);
    hex::decode(hexstr).unwrap()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn decode_base64(b64: &str) -> Vec<u8> {
    let b64 = purge_ws(b64);
    base64::decode(&b64).unwrap()
}

pub fn encode_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

pub fn hex_to_base64(hexstr: &str) -> String {
    encode_base64(&decode_hex(hexstr))
}

pub fn single_xor(inp: &[u8], k: u8) -> Vec<u8> {
    inp.iter().map(|x| x ^ k).collect()
}

pub fn repeat_xor(inp: &[u8], k: &[u8]) -> Vec<u8> {
    k.iter()
        .cycle()
        .zip(inp.iter())
        .map(|(k, x)| k ^ x)
        .collect()
}

pub fn block_xor(a: &mut [u8], b: &[u8]) {
    assert!(a.len() == b.len());
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    assert!(a.len() == b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

pub fn load_str(path: &str) -> String {
    fs::read_to_string(path).unwrap()
}

pub fn load_file(path: &str) -> Vec<u8> {
    fs::read(path).unwrap()
}

/// Returns up to the last n items in slice.
/// If the `slice.len() <= n`, entire slice is returned
pub fn lastn<T>(slice: &[T], n: usize) -> &[T] {
    if n == 0 {
        &[]
    } else if slice.len() > 0 {
        slice.rchunks(n).next().unwrap()
    } else {
        slice
    }
}

/// Returns up to the last n items in slice.
/// If the `slice.len() <= n`, entire slice is returned
pub fn lastn_mut<T>(slice: &mut [T], n: usize) -> &mut [T] {
    if n == 0 {
        &mut []
    } else if slice.len() > 0 {
        slice.rchunks_mut(n).next().unwrap()
    } else {
        slice
    }
}

/// https://tools.ietf.org/html/rfc5652#section-6.3
/// Always pad, so even if already multiple, pad entire block
pub fn pkcs7_pad(buf: &mut Vec<u8>, blocksize: u8) {
    let blocksize = blocksize as usize;
    let padsize = blocksize - (buf.len() % blocksize);
    let padbyte = padsize as u8;
    buf.extend(std::iter::repeat(padbyte).take(padsize));
}

pub fn pkcs7_validate(inp: &[u8]) -> Option<&[u8]> {
    let padbyte = inp[inp.len() - 1];
    if padbyte == 0 {
        return None;
    }
    let padlen = padbyte as usize;
    let padding = lastn(inp, padlen);
    if padding.iter().all(|x| *x == padbyte) {
        return Some(&inp[..(inp.len() - padlen)]);
    } else {
        return None;
    }
}

/*
/// If padded according to pkcs7_validate, return the unpadded
/// result from it. Otherwise return original input.
pub fn pkcs7_unpad(inp: &[u8]) -> &[u8] {
    match pkcs7_validate(inp) {
        Some(slice) => slice,
        None => inp,
    }
}
*/

pub fn rnd(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random()).collect()
}

/// Both inclusive
pub fn rnd_interval(min: usize, max: usize) -> usize {
    let x: usize = rand::random();
    return (x % (max - min + 1)) + min;
}

pub fn cmp_blocks(a: &[u8], b: &[u8]) -> bool {
    assert!(a.len() == b.len());
    a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

pub fn blackbox_aes() -> &'static aes128::Aes128 {
    aes_blackbox::blackbox()
}

// Functional aes ecb encrypt
pub fn ecb(aes: &aes128::Aes128, plain: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(plain);
    aes.ecb_encr(&mut buf);
    return buf;
}

/// returns ceil(lhs/rhs) without any float conversion
pub fn ceil_int_div<T>(lhs: T, rhs: T) -> T
where
    T: Into<usize> + std::convert::TryFrom<usize>,
{
    let lhs: usize = lhs.into();
    let rhs: usize = rhs.into();
    let r = if lhs % rhs == 0 {
        T::try_from(lhs / rhs)
    } else {
        T::try_from(lhs / rhs + 1)
    };
    // Throw away non printable error before unwrap
    return r.ok().expect("Integers are broken");
}

/// Returns
///   keybyte resulting in lowest (best) score
///   the resulting score
///   the scorer's output (transformed input),
/// None -> Not a single keybyte gave acceptable input to scorer
pub fn crack_single_xor<F, S, O>(scorer: F, inp: &[u8]) -> Option<(u8, S, O)>
where
    F: Fn(&[u8]) -> Option<(S, O)>,
    S: Ord + Copy,
{
    (0..=255)
        .filter_map(|k| {
            let v = single_xor(inp, k);
            scorer(&v).map(|(score, out)| (k, score, out))
        })
        .min_by_key(|(_, score, _)| *score)
}

pub struct Clock(u32);

impl Clock {
    pub fn now() -> Self {
        let t = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("What year is it?");
        Clock(t.as_secs() as u32)
    }

    pub fn wait(&mut self, seconds: u32) {
        self.0 += seconds;
    }

    /// Waits a random number of seconds
    pub fn waitsome(&mut self) {
        let t = rnd_interval(0, 9) as u32;
        self.wait(t);
    }

    pub fn timestamp(&self) -> u32 {
        self.0
    }
}
