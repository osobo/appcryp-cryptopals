use cryptopals::code::{self, Clock};

use rand;
use rayon::prelude::*;
use std::iter::once;

fn bytes_of_word(w: u32) -> impl Iterator<Item = u8> {
    let mask = 0x000000ffu32;
    let a = ((w >> 0) & mask) as u8;
    let b = ((w >> 8) & mask) as u8;
    let c = ((w >> 16) & mask) as u8;
    let d = ((w >> 24) & mask) as u8;
    once(a).chain(once(b)).chain(once(c)).chain(once(d))
}

fn keystream(key: u16) -> impl Iterator<Item = u8> {
    code::MT19937::new(key as u32).map(bytes_of_word).flatten()
}

fn encrypt(key: u16, inp: &mut [u8]) {
    inp.iter_mut()
        .zip(keystream(key))
        .for_each(|(x, k)| *x ^= k)
}

fn encr_and_show(key: u16, inp: &mut [u8]) {
    println!("{:02x?}\n->", inp);
    encrypt(key, inp);
    println!("{:02x?}", inp);
}

#[allow(dead_code)]
fn quick_test() {
    let key = 0x1234;
    let mut buf1 = [0; 8];
    let mut buf2 = [0x7d, 0x5d, 0x37, 0xc0, 0x42, 0xe4, 0xe5, 0x66];
    encr_and_show(key, &mut buf1);
    println!("\n\n");
    encr_and_show(key, &mut buf2);
    println!("\n\n");
    encr_and_show(key, &mut buf2);
}

const KNOWN_PLAINTEXT: &'static [u8] = b"AAAAAAAAAAAAAA";

/// Encrypts KNOWN_PLAINTEXT prefixed by random amount of random chars.
/// Uses random key
fn prefix_encr() -> Vec<u8> {
    let rndlen = code::rnd_interval(8, 127);
    let rnds = code::rnd(rndlen);
    let mut buf = Vec::from(rnds);
    buf.extend(KNOWN_PLAINTEXT);
    let key = rand::random();
    println!("Real key = {}", key);
    encrypt(key, &mut buf);
    return buf;
}

fn recover_key(cipher: &[u8]) -> u16 {
    // TODO: Just gonna bruteforce 16-bits, ok?
    let target_keystream = {
        // The encrypted KNOWN_PLAINTEXT
        let mut buf = Vec::from(code::lastn(cipher, KNOWN_PLAINTEXT.len()));
        // xor with plain to get keytream
        code::block_xor(&mut buf, KNOWN_PLAINTEXT);
        buf
    };
    let to_skip = cipher.len() - target_keystream.len();
    // Try all possible keys until get right section of keystream
    (0..=u16::max_value())
        .into_par_iter()
        .filter(|k| {
            keystream(*k)
                .skip(to_skip)
                .zip(target_keystream.iter())
                .all(|(a, b)| a == *b)
        })
        .find_any(|_| true)
        .expect("No u16 gave matching keystream")
}

fn token_from_seed(seed: u32) -> String {
    let len = 12;
    let bytes: Vec<u8> = code::MT19937::new(seed)
        .take(len)
        .map(bytes_of_word)
        .flatten()
        .collect();
    return code::encode_base64(&bytes);
}

fn new_token(clock: &mut Clock) -> String {
    clock.waitsome();
    let seed = clock.timestamp(); // + 200;
    println!("Creating new token using seed {}", seed);
    return token_from_seed(seed);
}

/// Checks if token was created using system time within the last minute
fn check_token(clock: &Clock, token: &str) {
    let beg = clock.timestamp();
    let end = beg + 60;
    match (beg..end)
        .into_par_iter()
        .map(|time| (time, token_from_seed(time)))
        .find_any(|(_, tok)| tok == token)
    {
        Some((time, _)) => println!("Time {} was used as seed", time),
        None => println!("No recent time was used as seed"),
    }
}

#[allow(dead_code)]
fn demo_recover_key() {
    let cipher = prefix_encr();
    let k = recover_key(&cipher);
    println!("Recoved {}", k);
}

#[allow(dead_code)]
fn demo_token() {
    let mut clock = Clock::now();
    let token = new_token(&mut clock);
    println!("Token: {}", token);
    check_token(&clock, &token);
}

fn main() {
    //demo_recover_key();
    demo_token();
}
