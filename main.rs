use rand::seq::SliceRandom;
use rand::Rng;
mod words;
use words::WORDLIST;

fn main() {
    let mut rng = rand::thread_rng();
    let password: String = (0..3)
        .map(|_| WORDLIST.choose(&mut rng).unwrap().to_string())
        .collect::<Vec<String>>()
        .join("-")
        .to_string();

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

    let position = rng.gen_range(0..4);
    let mut password_vec: Vec<&str> = password.split("-").collect();
    password_vec.insert(position, &segment);
    let final_password = password_vec.join("-");
    println!("{}", final_password);
}
