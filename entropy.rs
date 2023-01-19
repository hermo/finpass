// bruteForceEntropy calculates the entropy of a password based on the number of
// characters and character classes used
pub fn bruteforce_entropy(password: &str) -> f64 {
    // deduce character classes used from password. Classes include lowercase,
    // uppercase, digits, and symbols
    let mut lowercase = false;
    let mut uppercase = false;
    let mut digits = false;
    let mut symbols = false;
    for c in password.chars() {
        match c {
            'a'..='z' => lowercase = true,
            'A'..='Z' => uppercase = true,
            '0'..='9' => digits = true,
            _ => symbols = true,
        }
    }
    // add the number of characters in each class used
    let mut characters = 0;
    if lowercase {
        characters += 26;
    }
    if uppercase {
        characters += 26;
    }
    if digits {
        characters += 10;
    }
    if symbols {
        characters += 10;
    }

    (password.len() as f64) * (characters as f64).log2()
}

pub fn wordlist_entropy(password: &str, separator: char, wordlist_size: usize) -> f64 {
    // count the number of words in the password.
    // exclude one word because it is assumed to be the random one.
    let word_count = password.chars().filter(|c| c == &separator).count();
    let words_ent = word_count as f64 * (wordlist_size as f64).log2();

    // calculate entropy increase from the separator. there are 3 separators and they are always -
    let separator_ent = 3f64.log2();

    // one word is always 3 characters long and contains uppercase letters and one or more digits
    let random_ent = 3f64 * 36f64.log2();

    words_ent + separator_ent + random_ent
}

pub fn estimate_time_to_crack(entropy: f64) -> String {
    // Assume the cracking speed is 20MH/s
    // Estimate based on RTX 4090 Hashcat benchmarks
    // https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
    let guesses_per_second: f64 = 20e6;
    // calculate the number of guesses needed to crack the password
    let guesses: f64 = 2.0_f64.powf(entropy);
    // calculate the number of seconds needed to crack the password
    let seconds: f64 = guesses / guesses_per_second;
    // calculate minutes needed to crack the password
    let minutes: f64 = seconds / 60.0_f64;
    // calculate hours needed to crack the password
    let hours: f64 = seconds / 60.0_f64 / 60.0_f64;
    // calculate days needed to crack the password
    let days: f64 = seconds / 60.0_f64 / 60.0_f64 / 24.0_f64;
    // calculate the number of years needed to crack the password
    let years: f64 = seconds / 60.0_f64 / 60.0_f64 / 24.0_f64 / 365.0_f64;
    // calculate the number of centuries needed to crack the password
    let centuries: f64 = years / 100.0_f64;
    // calculate thousands of years needed to crack the password
    let thousands_of_years: f64 = years / 1000.0_f64;
    // calculate millions of years needed to crack the password
    let millions_of_years: f64 = years / 1000000.0_f64;
    // calculate billions of years needed to crack the password
    let billions_of_years: f64 = years / 1000000000.0_f64;
    // calculate trillions of years needed to crack the password
    let trillions_of_years: f64 = years / 1000000000000.0_f64;
    // calculate quadrillions of years needed to crack the password
    let quadrillions_of_years: f64 = years / 1000000000000000.0_f64;
    // calculate quintillions of years needed to crack the password
    let quintillions_of_years: f64 = years / 1000000000000000000.0_f64;
    // calculate sextillions of years needed to crack the password
    let sextillions_of_years: f64 = years / 1000000000000000000000.0_f64;
    // calculate septillions of years needed to crack the password
    let septillions_of_years: f64 = years / 1000000000000000000000000.0_f64;
    // calculate octillions of years needed to crack the password
    let octillions_of_years: f64 = years / 1000000000000000000000000000.0_f64;
    // calculate nonillions of years needed to crack the password
    let nonillions_of_years: f64 = years / 1000000000000000000000000000000.0_f64;
    // return the appropriate number of years, centuries, millennia, or aeons as a formatted string with
    // 0 decimal places until "years" when it switches to 1 decimal place. seconds is always 0 decimal places.
    // start with the largest unit of time and work down to seconds.
    // example: ~42 nonillion years
    if nonillions_of_years >= 1.0_f64 {
        format!("~{:.0} nonillion years", nonillions_of_years)
    } else if octillions_of_years >= 1.0_f64 {
        format!("~{:.0} octillion years", octillions_of_years)
    } else if septillions_of_years >= 1.0_f64 {
        format!("~{:.0} septillion years", septillions_of_years)
    } else if sextillions_of_years >= 1.0_f64 {
        format!("~{:.0} sextillion years", sextillions_of_years)
    } else if quintillions_of_years >= 1.0_f64 {
        format!("~{:.0} quintillion years", quintillions_of_years)
    } else if quadrillions_of_years >= 1.0_f64 {
        format!("~{:.0} quadrillion years", quadrillions_of_years)
    } else if trillions_of_years >= 1.0_f64 {
        format!("~{:.0} trillion years", trillions_of_years)
    } else if billions_of_years >= 1.0_f64 {
        format!("~{:.0} billion years", billions_of_years)
    } else if millions_of_years >= 1.0_f64 {
        format!("~{:.0} million years", millions_of_years)
    } else if thousands_of_years >= 1.0_f64 {
        format!("~{:.0} thousand years", thousands_of_years)
    } else if centuries >= 1.0_f64 {
        format!("~{:.0} centuries", centuries)
    } else if years >= 1.0_f64 {
        format!("~{:.1} years", years)
    } else if days >= 1.0_f64 {
        format!("~{:.1} days", days)
    } else if hours >= 1.0_f64 {
        format!("~{:.1} hours", hours)
    } else if minutes >= 1.0_f64 {
        format!("~{:.1} minutes", minutes)
    } else if seconds >= 1.0_f64 {
        format!("~{:.0} seconds", seconds)
    } else {
        format!("instantly")
    }
}
