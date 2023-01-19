use rand::seq::SliceRandom;
use rand::Rng;
mod words;
use clap::Parser;

mod entropy;
use entropy::{bruteforce_entropy, estimate_time_to_crack, wordlist_entropy};
use words::WORDLIST;

fn generate_password(max_length: usize) -> String {
    let mut rng = rand::thread_rng();
    let wordlist = get_words(max_length);
    // Generate the first three words
    let mut password_vec = (0..3)
        .map(|_| wordlist.choose(&mut rng).unwrap().to_string())
        .collect::<Vec<String>>();

    // Generate the last three characters
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

    // Determine the position of the last three characters
    let position = rng.gen_range(0..4);

    // Combine the first three words and the last three characters
    password_vec.insert(position, segment);
    password_vec.join("-")
}

// Create function that returns words from WORDLIST having a maximum length max_length
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
    #[arg(short, long, default_value_t = 0)]
    max_length: u8,
    /// Show entropy and estimated time to crack. The flag should be -i or --info
    #[arg(short, long)]
    info: bool,
}

fn main() {
    let args = Args::parse();
    if args.max_length != 0 && args.max_length < 3 {
        eprintln!("Maximum word length must be at least 3");
        std::process::exit(1);
    }
    let password = generate_password(args.max_length as usize);
    println!("{}", password);

    if args.info {
        let brute_ent = bruteforce_entropy(&password);
        let words_ent = wordlist_entropy(&password, '-', WORDLIST.len());
        eprintln!("Entropy and estimated time to crack using a fast GPU-based attack (20 MH/s, one or more RTX 4090):");
        eprintln!(
            "* Brute-force:    {:5.1} bits ({})",
            brute_ent,
            estimate_time_to_crack(brute_ent)
        );
        eprintln!(
            "* Known wordlist: {:5.1} bits ({})",
            words_ent,
            estimate_time_to_crack(words_ent)
        );
        if args.max_length > 0 {
            let words = get_words(args.max_length as usize);
            let words_ent = wordlist_entropy(&password, '-', words.len());
            eprintln!(
                "* Known wordlist and parameters (-m={}): {:5.1} bits ({})",
                args.max_length,
                words_ent,
                estimate_time_to_crack(words_ent)
            );
        }
    }
}
