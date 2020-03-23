use cryptopals::code;

use lazy_static::*;
use rayon::prelude::*;
use std::iter::{once, repeat};

const VICTIM_B64: &str = concat!(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg",
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq",
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg",
    "YnkK"
);

lazy_static! {
    static ref VICTIM_PLAIN: Vec<u8> = code::decode_base64(VICTIM_B64);
}

/// AES-128-ECB(random-prefix || attacker-controlled || target-bytes,
///             random-key)
fn prepend_ecb(attacker_prefix: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = rnd_prefix()
        .into_iter()
        .chain(attacker_prefix.iter().copied())
        .chain(VICTIM_PLAIN.iter().copied())
        .collect();
    code::blackbox_aes().ecb_encr(&mut buf);
    return buf;
}

fn rnd_prefix() -> Vec<u8> {
    let count = code::rnd_interval(0, 1023);
    return code::rnd(count);
}

/// Tries different prefix lengths multiple times and records all resulting
/// ciphertext lengths.
/// Returns the largest power of 2 that divides all lengths.
fn find_blocksize() -> usize {
    // Number of different prefixes to test
    let prefixes = 100;
    // Number of tests per prefix length
    let samples = 100;

    let prefix = vec![0u8; prefixes];
    let mut lens: Vec<_> = (0..prefixes)
        .into_par_iter()
        .map(|pref_len| {
            rayon::iter::repeatn(pref_len, samples)
                .map(|l| prepend_ecb(&prefix[0..l]).len())
        })
        .flatten()
        .collect();

    // Annoying to do true gcd on all of lens.
    // Just going to guess that it's a power of two and try all
    lens.sort();
    lens.dedup();
    let longest = lens[lens.len() - 1];
    let mut guess = longest.next_power_of_two();
    while guess > 1 {
        // If guess divides all in lens, guess is greatest power of 2
        // that divides all
        if lens.iter().all(|l| l % guess == 0) {
            return guess;
        } else {
            guess /= 2;
        }
    }
    return 1;
}

/// Finds what the AES([b,b,...,b], hidden_key) is
fn find_cipherblock_rep(b: u8, blocksize: usize) -> Vec<u8> {
    // Prepend 3 copies so there must be two full blocks,
    // regardless of random length.
    let prefix = vec![b; 3 * blocksize];
    let cipher = prepend_ecb(&prefix);
    let blocks: Vec<_> = cipher.chunks_exact(blocksize).collect();
    for i in 1..blocks.len() {
        let prev = blocks[i - 1];
        let this = blocks[i];
        if code::cmp_blocks(prev, this) {
            return this.into();
        }
    }
    // Can only get here if no two consecutive cipher blocks are identical,
    // which should be impossible.
    unreachable!();
}

/// Finds the first instance of `count` consecutive `targetblock` in `cipher`.
/// Returns the block index of the first matching block.
fn idx_of_first_matches(
    cipher: &[u8],
    targetblock: &[u8],
    count: usize,
) -> Option<usize> {
    let blocksize = targetblock.len();
    let mut matches = 0usize; // Number of consecutive matches found so far
    for i in 0..(cipher.len() / blocksize) {
        let blk = &cipher[(i * blocksize)..((i + 1) * blocksize)];
        if code::cmp_blocks(blk, targetblock) {
            matches += 1;
        } else {
            matches = 0;
        }
        if matches == count {
            return Some(i + 1 - count);
        }
    }
    return None;
}

const ALIGNMENT_BLOCKS: usize = 10;
const ALIGNMEN_TRASH: u8 = 1;

// Runs oracle multiple times until given prefix is block aligned.
struct Aligner {
    blocksize: usize,
    cipher0: Vec<u8>,
}

impl Aligner {
    fn new(blocksize: usize) -> Self {
        let cipher0 = find_cipherblock_rep(0, blocksize);
        Self { blocksize, cipher0 }
    }

    /// Returns iterator over new pre_prefix
    fn pre_prefix(&self) -> impl Iterator<Item = u8> {
        // Need range of 0..blocksize but want to guarantee to
        // always have at least one trash byte
        let rnd_count = code::rnd_interval(1, self.blocksize);
        let it = repeat(ALIGNMEN_TRASH)
            .take(rnd_count)
            .chain(repeat(0).take(ALIGNMENT_BLOCKS * self.blocksize));
        return it;
    }

    /// Returns a cipher where `prefix` is block-aligned,
    /// and the block index of the first block of `prefix`
    fn aligned_cipher(&self, prefix: &[u8]) -> (usize, Vec<u8>) {
        rayon::iter::repeat(())
            .filter_map(|_| {
                let prefix_buf: Vec<_> =
                    self.pre_prefix().chain(prefix.iter().copied()).collect();
                let cipher = prepend_ecb(&prefix_buf);
                let idx = idx_of_first_matches(
                    &cipher,
                    &self.cipher0,
                    ALIGNMENT_BLOCKS,
                );
                // idx is block idx to start of our prefix with
                // the alignment blocks, but not with trash
                idx.map(|idx| (idx + ALIGNMENT_BLOCKS, cipher))
            })
            .find_any(|_| true)
            .expect("Somehow ran infinite attempts and all failed")
    }
}

/// `plain_prefix` = [p0, p1, ...]` of length `blocksize-1`
/// `target_cipher` = `EncryptBlock(plain_prefix+b, secret_key)`
/// for some plain byte `b`.
/// Bruteforces to find what that `b` is.
fn spin_block(
    aligner: &Aligner,
    plain_prefix: &[u8],
    target_cipher: &[u8],
) -> Option<u8> {
    assert!(plain_prefix.len() == aligner.blocksize - 1);
    // Exactly one block
    let mut prefix: Vec<_> =
        plain_prefix.iter().copied().chain(once(0)).collect();
    for b in 0..=255 {
        prefix[aligner.blocksize - 1] = b;
        let (pref_idx, cipher) = aligner.aligned_cipher(&prefix);
        let target_block = cipher
            .chunks_exact(aligner.blocksize)
            .skip(pref_idx)
            .next()
            .unwrap();
        if code::cmp_blocks(target_block, target_cipher) {
            return Some(b);
        }
    }
    return None;
}

const CRACK_TRASH: u8 = 2u8;

// If plain already contains the entire victim plaintext this will result
// in returning 0x01 since that is what will be followed by the plaintext
// after padding.
// If plain contains something that is not in the plantext
// (like a trailing 0x01) this will fail and return None.
fn crack_next(aligner: &Aligner, plain: &[u8]) -> Option<u8> {
    let blocksize = aligner.blocksize;
    // Number of bytes needed to prepend so "target byte" is last byte is a
    // in a plain block.
    let trash_needed = blocksize - 1 - (plain.len() % blocksize);
    let prefix: Vec<_> = repeat(CRACK_TRASH).take(trash_needed).collect();
    // pref_idx is is the block index in cipher that contains our prefix.
    // Thus the block following it (pref_idx+1) contains the start of the
    // victim plaintext.
    let (pref_idx, cipher) = aligner.aligned_cipher(&prefix);
    // Skipping our prefix then the length of plain means we get the block
    // containing the target byte, which will be last of that block:
    let known_cipher = cipher
        .chunks_exact(blocksize)
        .skip(pref_idx)
        .skip(plain.len() / blocksize)
        .next()
        .unwrap();

    let plain_end = code::lastn(plain, blocksize - 1);
    let trash_needed = (blocksize - 1) - plain_end.len();
    // If plain is already blocksize-1 long, this will be those last bytes.
    // If plain is shorter, it is padded in the same way as earlier.
    // Ie, this is the first blocksize-1 plain bytes of the plain block
    // which produced known_cipher.
    let plain_block: Vec<_> = repeat(CRACK_TRASH)
        .take(trash_needed)
        .chain(plain_end.iter().copied())
        .collect();
    // If plain (and therefore plain_block) contains something that isn't in
    // the victim plaintext this will return None.
    return spin_block(&aligner, &plain_block, &known_cipher);
}

fn main() {
    let bs = find_blocksize();
    let aligner = Aligner::new(bs);
    let mut plain_bytes = Vec::new();
    while let Some(b) = crack_next(&aligner, &plain_bytes) {
        plain_bytes.push(b);
        println!("{:02x?}", plain_bytes);
        let s = String::from_utf8(plain_bytes.clone());
        if let Ok(s) = s {
            println!("{}", s);
        }
        println!("\n");
    }

    let final_plain_bytes = &plain_bytes[..(plain_bytes.len()-1)];
    let final_plain_str = String::from_utf8(Vec::from(final_plain_bytes))
        .unwrap_or_else(|_| String::from("NOT UTF8"));
    println!("Final answer\n{:02x?}\n{}", final_plain_bytes, final_plain_str);
}
