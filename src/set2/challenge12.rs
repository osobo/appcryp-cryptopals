use cryptopals::code;

use lazy_static::*;
use std::iter::{once, repeat};

const TXT: &str = r"
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
";

lazy_static! {
    static ref VICTIM_PLAIN: Vec<u8> = code::decode_base64(&TXT);
}

fn prepend_ecb(inp: &[u8]) -> Vec<u8> {
    let mut buf: Vec<_> =
        inp.iter().chain(VICTIM_PLAIN.iter()).copied().collect();
    code::blackbox_aes().ecb_encr(&mut buf);
    return buf;
}

fn find_blocksize() -> usize {
    let mut lens = (0..).map(|l| prepend_ecb(&vec![0; l]).len());
    let fst = lens.next().unwrap();
    let next = lens.find(|l| *l != fst).unwrap();
    return next - fst;
}

fn detect_ecb(blocksize: usize) -> bool {
    let cipher = prepend_ecb(&vec![0; blocksize * 2]);
    let fst = &cipher[0..blocksize];
    let snd = &cipher[blocksize..(2 * blocksize)];
    return code::cmp_blocks(fst, snd);
}

/// Gets the cipher block to compare against by prepending the right number of
/// zeros to place the target byte at the last index of the block.
fn get_target_cipher_block(
    blocksize: usize,
    blk: usize,
    zero_count: usize,
) -> Vec<u8> {
    let prefix = vec![0u8; zero_count];
    let cipher = prepend_ecb(&prefix);
    return Vec::from(
        &cipher[(blk * blocksize)..(blk * blocksize + blocksize)],
    );
}

fn bruteforce_next(target: &[u8], block: &mut [u8]) -> u8 {
    let bs = target.len();
    for b in 0u8..=255u8 {
        block[bs - 1] = b;
        let res = &prepend_ecb(&block)[0..bs];
        if code::cmp_blocks(&target, res) {
            return b;
        }
    }
    unreachable!();
}

fn crack_next(blocksize: usize, plain: &[u8]) -> u8 {
    // We know first k bytes
    let k = plain.len();
    // target byte is in block blk at index i
    let blk = k / blocksize;
    let i = k % blocksize;
    // By prepending this number of zeros the target plain byte
    // will be placed as the last byte in blk.
    let zero_count = blocksize - i - 1;
    let target = get_target_cipher_block(blocksize, blk, zero_count);
    assert!(target.len() == blocksize);
    let mut block: Vec<_> = if k < blocksize - 1 {
        // This should add up to exactly one block
        repeat(0)
            .take(zero_count)
            .chain(plain.iter().copied())
            .chain(once(0)) // The last byte to cycle over
            .collect()
    } else {
        let first_plain = k - (blocksize - 1);
        plain[first_plain..k]
            .iter()
            .copied()
            .chain(once(0))
            .collect()
    };
    assert!(block.len() == blocksize);
    return bruteforce_next(&target, &mut block);
}

fn main() {
    let blocksize = find_blocksize();
    println!("Blocksize = {}", blocksize);

    assert!(detect_ecb(blocksize));

    let mut plain = vec![];
    while plain.len() < VICTIM_PLAIN.len() {
        let next_plain = crack_next(blocksize, &plain);
        plain.push(next_plain);
        let s = String::from_utf8(plain.clone()).unwrap();
        println!("Found {} plain bytes so far: [{}]\n", plain.len(), s);
    }

    let s = String::from_utf8(plain).unwrap();
    println!("Final result:\n{}", s);
}
