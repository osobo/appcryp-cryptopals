
use std::collections::HashMap;
use std::iter::{FromIterator};
use lazy_static::*;

const FREQ_BASE: usize = 1_000_000;
static FREQS: [u32;54] = [
    157677, 21185, 55718, 1959,  10205, 1002,
     22916,  1002, 40273, 1230, 111435, 1276,
     16219,   501, 17039,  410,  24784, 1503,
     58770,  1276,  1686,  137,   3690,  137,
     33303,   501, 24556, 1093,  64920,  501,
     59636,  1640, 18633,  911,   1686,   91,
     53303,   729, 54761, 2460,  58633, 1002,
     24191,   410,  8702,   91,  12802, 1139,
     3144,      0, 18770,  182,    182,    0
];
static LETTERS: &str = 
    " .aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ";

lazy_static! {
    static ref LETTER_FREQ: HashMap<char,u32> = HashMap::from_iter(
        LETTERS.chars().zip(FREQS.iter())
            .map(|(l,f)| (l,*f))
    );
}

fn score(inp: &str) -> u64 {
    let mut cnts: HashMap<char,u32> = HashMap::from_iter(
        LETTERS.chars().map(|l| (l,0u32))
    );
    let mut tot = 0;
    for c in inp.chars() {
        if ! c.is_ascii() { return u64::max_value() }
        if let Some(cnt) = cnts.get(&c).copied() {
            cnts.insert(c, cnt + 1);
            tot += 1;
        }
    }
    cnts.into_iter().map(|(c,cnt)| {
        let ratio = (cnt as f64) / (tot as f64);
        let freq = ((FREQ_BASE as f64) * ratio) as u32;
        let diff = (freq as i64) - (LETTER_FREQ[&c] as i64);
        let err = diff.abs() as u64;
        err
    }).sum()
}

pub fn scorer(inp: &[u8]) -> Option<(u64, String)> {
    String::from_utf8(Vec::from(inp))
        .map(|s| (score(&s), s))
        .ok()
}
