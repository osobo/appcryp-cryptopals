use cryptopals::code::{self,Clock};

/// The described routine
/// Returns the generated value and the used seed
fn routine(clock: &mut Clock) -> (u32, u32) {
    let prewait = code::rnd_interval(40, 1000) as u32;
    clock.wait(prewait);
    let seed = clock.timestamp();
    let mut rng = code::MT19937::new(seed);
    let postwait = code::rnd_interval(40, 1000) as u32;
    clock.wait(postwait);
    return (rng.get_next(), seed);
}

fn main() {
    // TODO: Just gonna bruteforce, supposed to do other way?
    let mut clock = Clock::now();
    let start = clock.timestamp();
    let (target, real_seed) = routine(&mut clock);
    let guess_seed = (start..)
        .skip_while(|seed| {
            let mut rng = code::MT19937::new(*seed);
            let x = rng.get_next();
            x != target
        })
        .next()
        .unwrap();
    println!("Real seed is {}\nGuess is {}", real_seed, guess_seed);
}
