
use cryptopals::code;
use rand;

fn crack_state<I>(it: I) -> code::MT19937
where I: Iterator<Item=u32>
{
    let v: Vec<_> = it.take(624).map(code::mt19937::untemper).collect();
    return code::MT19937::from_state(&v, 0);
}

fn main() {
    let old = code::MT19937::new(rand::random());
    let new = crack_state(old.clone());
    let old_nums: Vec<_> = old.take(10).collect();
    let new_nums: Vec<_> = new.take(10).collect();
    println!("{:?}\n{:?}", old_nums, new_nums);
}
