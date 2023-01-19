use rand::seq::SliceRandom;
use rand::Rng;
mod words;
use clap::Parser;

mod entropy;
use entropy::{bruteforce_entropy, estimate_time_to_crack, wordlist_entropy};
use words::WORDLIST;

/// Generate a password.
/// The returned password is a combination of three words and three random characters, separated by dashes.
/// The max_length parameter allows limiting the length of the words used in the password. Use 0 to allow any length.
fn generate_password(max_word_length: usize) -> String {
    let mut rng = rand::thread_rng();
    let wordlist = get_words(max_word_length);

    // Generate the word segments of the password
    let mut password_vec = (0..3)
        .map(|_| wordlist.choose(&mut rng).unwrap().to_string())
        .collect::<Vec<String>>();

    // Generate the alphanumeric segment
    let mut segment = String::new();
    let mut has_char = false;
    let mut has_num = false;

    while segment.len() < 3 || !(has_char && has_num) {
        has_char = false;
        has_num = false;
        segment.clear();
        for _ in 0..3 {
            let c = rng.gen::<u8>();
            if c >= b'0' && c <= b'9' {
                has_num = true;
                segment.push(c as char);
            } else if c >= b'A' && c <= b'Z' {
                has_char = true;
                segment.push(c as char);
            }
        }
    }

    // Determine position to insert alphanumeric segment
    let position = rng.gen_range(0..4);

    // Combine the segments
    password_vec.insert(position, segment);
    password_vec.join("-")
}

/// Get a list of words from the wordlist that are shorter than the max_length parameter.
fn get_words(max_length: usize) -> Vec<&'static str> {
    if max_length == 0 {
        return WORDLIST.to_vec();
    }
    WORDLIST
        .iter()
        .filter(|word| word.len() <= max_length)
        .map(|word| *word)
        .collect()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Maximum length of each word in the password
    #[arg(short = 'm', default_value_t = 0)]
    max_word_length: u8,
    /// Show information regarding entropy and estimated time to crack
    #[arg(short = 'i', default_value_t = false)]
    show_info: bool,
}

fn main() {
    let args = Args::parse();
    if args.max_word_length != 0 && args.max_word_length < 3 {
        eprintln!("Maximum word length must be at least 3");
        std::process::exit(1);
    }

    let password = generate_password(args.max_word_length as usize);
    println!("{}", password);

    if args.show_info {
        let brute_ent = bruteforce_entropy(&password);
        let wordlist_ent = wordlist_entropy(&password, '-', WORDLIST.len());

        eprintln!("Entropy and estimated time to crack using a fast GPU-based attack (20 MH/s, one or more RTX 4090):");
        eprintln!(
            "* Brute-force:    {:5.1} bits ({})",
            brute_ent,
            estimate_time_to_crack(brute_ent)
        );

        eprintln!(
            "* Known wordlist: {:5.1} bits ({})",
            wordlist_ent,
            estimate_time_to_crack(wordlist_ent)
        );

        if args.max_word_length > 0 {
            let words = get_words(args.max_word_length as usize);
            let words_ent = wordlist_entropy(&password, '-', words.len());
            eprintln!(
                "* Known wordlist and parameters (-m={}): {:5.1} bits ({})",
                args.max_word_length,
                words_ent,
                estimate_time_to_crack(words_ent)
            );
        }
    }
}
