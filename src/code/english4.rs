/// Based on order of freq of the plains from ch20
pub mod cheaty {
    const ORDERED: &str =
        " etaoinsrhuldmyc,'pfw/gkIbv-TS!AYMCzFR.EBj?xWNqPH\"OD;LK:ZJ4";

    fn score_str(s: &str) -> u64 {
        let worst = ORDERED.len() * s.len();
        s.chars()
            .map(|c| ORDERED.find(c).unwrap_or(worst) as u64)
            .sum()
    }

    pub fn scorer(inp: &[u8]) -> Option<(u64, String)> {
        String::from_utf8(Vec::from(inp))
            .map(|s| (score_str(&s), s))
            .ok()
    }
}
