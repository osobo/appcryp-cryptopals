
use cryptopals::code::MT19937;

fn main() {
    let n: Vec<_> = MT19937::default().take(10).collect();
    println!("{:?}", n);
}
