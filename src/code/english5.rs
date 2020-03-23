
// Based off randomly generated english text
const CHAR_ORDER: &str =
    " enoitasrdlhmuc.ypgfwbvkxSAqjOHIEDWMTCBPRNLFUGzYKJVQZX";

fn is_ok(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

fn score_str(s: &str) -> u64 {
    // It there's a single horrible (not ok) char, sum will be higher than
    // a string full of uncommon chars
    let horrible = CHAR_ORDER.len() * s.len() * 2;
    let uncommon = CHAR_ORDER.len();
    s.chars()
        .map(|c| {
            if is_ok(c) {
                CHAR_ORDER.find(c).unwrap_or(uncommon) as u64
            } else {
                horrible as u64
            }
        })
        .sum()
}

pub fn scorer(inp: &[u8]) -> Option<(u64, String)> {
    String::from_utf8(Vec::from(inp))
        .map(|s| (score_str(&s), s))
        .ok()
}
