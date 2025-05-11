use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::exit,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use clap::Parser;
use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, FromBase64, VerifyingAlgorithm};
use rayon::{ThreadPoolBuilder, prelude::*};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Parser, Debug)]
struct Args {
    /// JWT token to crack
    jwt: String,

    /// Path to the wordlist file containing potential secrets
    wordlist: PathBuf,
    
    /// Number of threads to use (0 means use default thread count)
    #[arg(short, long, default_value = "0")]
    threads: usize,
}

fn main() {
    let args = Args::parse();

    println!("warming up...");
    
    // Configure thread pool if specified
    if args.threads > 0 {
        ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .expect("Failed to build thread pool");
    }

    let wordlist = BufReader::new(File::open(&args.wordlist).expect("wordlist should exist"));

    // Count total words for progress reporting
    let total_words = BufReader::new(File::open(&args.wordlist).expect("wordlist should exist"))
        .lines()
        .count();

    // Calculate chunk size for progress reporting (minimum 1)
    let chunk = std::cmp::max(1, total_words / 100);

    let processed_words = Arc::new(AtomicUsize::new(0));

    let (algorithm, header, claims, signature) = split_jwt(&args.jwt).expect("bad jwt");

    // Create the key generator function based on algorithm type
    let create_key: fn(&[u8]) -> Box<dyn VerifyingAlgorithm> = match algorithm {
        AlgorithmType::Hs256 => |word| Box::new(Hmac::<Sha256>::new_from_slice(word).expect("this shouldn't fail")),
        AlgorithmType::Hs384 => |word| Box::new(Hmac::<Sha384>::new_from_slice(word).expect("this shouldn't fail")),
        AlgorithmType::Hs512 => |word| Box::new(Hmac::<Sha512>::new_from_slice(word).expect("this shouldn't fail")),
        AlgorithmType::None => {
            println!("None type specified - nothing to crack");
            exit(0);
        }
        _ => {
            eprintln!("Currently only deal with HS{{256, 384, 512}} algorithms -- if you want to implement other ones, please submit a PR");
            exit(1);
        }
    };

    wordlist.lines().par_bridge().for_each(|word| {
        let Ok(word) = word else {
            return;
        };

        let key = create_key(word.as_bytes());

        // Update progress counter
        let p = processed_words.fetch_add(1, Ordering::Relaxed);
        if p % chunk == 0 {
            print!("\r[alg: {:#?}] [total: {}]: {}%", key.algorithm_type(),total_words, (p * 100) / total_words);
            std::io::stdout().flush().unwrap();
        }
        
        if key.verify(header, claims, signature).unwrap_or(false) {
            println!("\nFound secret: {word:?}");
            exit(0)
        }
    });

    println!("\nNo secret found, try another wordlist.");
}

fn split_jwt(jwt: &str) -> Result<(AlgorithmType, &str, &str, &str), jwt::Error> {
    let mut components = jwt.split('.');
    let header = components.next().ok_or(jwt::Error::NoHeaderComponent)?;
    let claims = components.next().ok_or(jwt::Error::NoClaimsComponent)?;
    let signature = components.next().ok_or(jwt::Error::NoSignatureComponent)?;

    let algorithm = jwt::Header::from_base64(header)?.algorithm;

    Ok((algorithm, header, claims, signature))
}
