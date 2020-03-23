use cryptopals::code;

use std::collections::HashSet;

/// If ecb, return a block that appears twice
fn identify_ecb(inp: &[u8]) -> Option<&[u8]> {
    let mut blocks = HashSet::new();
    for block in inp.chunks_exact(code::aes128::BLOCKSIZE) {
        let new_block = blocks.insert(block);
        if !new_block {
            return Some(block);
        }
    }
    return None;
}

fn main() {
    let inp = code::load_str("challenge-data/8.txt");
    for l in inp.lines() {
        let bytes = code::decode_hex(l);
        if let Some(block) = identify_ecb(&bytes) {
            let blockhex = code::encode_hex(block);
            println!("{}\n->\n{}\n", l, blockhex);
        }
    }
}
