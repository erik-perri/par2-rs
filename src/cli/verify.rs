use crate::error::Par2Error;
use crate::set::Par2ParsedSet;
use crate::{file, packet, verify};
use std::path::Path;
use std::{fs, process};

pub(crate) fn verify(path: &Path) -> Result<(), Par2Error> {
    let primary_file = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\"{}\" is not a valid file: {}", path.display(), e);
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

    Ok(())
}
