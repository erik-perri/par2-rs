mod error;
mod file;
mod galois;
mod packet;
mod set;
mod verify;

use crate::set::Par2ParsedSet;
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("No file provided.");
        process::exit(1);
    }

    let arg = &args[1];
    let primary_file = match fs::canonicalize(arg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\"{}\" is not a valid file: {}", arg, e);
            process::exit(1);
        }
    };

    let file_paths = file::locate_files(&primary_file).unwrap_or_else(|e| {
        println!("Failed to locate files: {}", e);
        process::exit(1);
    });

    let mut packets = Vec::new();

    for file_path in file_paths {
        println!("Parsing file: {}", file_path.display());

        let parsed_packets = packet::parse_file(&file_path).unwrap_or_else(|e| {
            println!(
                "Failed to parse packets from {}: {}",
                file_path.display(),
                e
            );

            process::exit(1);
        });

        packets.extend(parsed_packets);
    }

    let potential_set = Par2ParsedSet::from_packets(packets).unwrap_or_else(|e| {
        println!("Failed to combine set: {}", e);
        process::exit(1);
    });

    let validated_set = potential_set.validate().unwrap_or_else(|e| {
        println!("Failed to validate set: {}", e);
        process::exit(1);
    });

    let base_path = primary_file
        .parent()
        .expect("canonicalized path should always have a parent");

    let verified_set = verify::verify_set(validated_set, base_path);

    println!("{:#?}", verified_set);
}
