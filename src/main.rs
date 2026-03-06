mod error;
mod file;
mod packet;
mod set;

use std::path::Path;
use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("No file provided.");
        process::exit(1);
    }

    let primary_file = Path::new(args.get(1).unwrap());
    let file_paths = file::locate_files(primary_file).unwrap_or_else(|e| {
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

    let set = set::combine_set(packets).unwrap_or_else(|e| {
        println!("Failed to combine set: {}", e);
        process::exit(1);
    });

    println!("{:#?}", set);
}
