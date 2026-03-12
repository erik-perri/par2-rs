use crate::error::Par2Error;
use crate::set::Par2ParsedSet;
use crate::{file, packet, verify};
use log::{debug, trace};
use std::path::Path;
use std::fs;

pub(crate) fn verify(path: &Path) -> Result<(), Par2Error> {
    let primary_file = fs::canonicalize(path)?;

    let file_paths = file::locate_files(&primary_file)?;

    let mut packets = Vec::new();

    for file_path in file_paths {
        debug!("Parsing file: {}", file_path.display());

        let parsed_packets = packet::parse_file(&file_path)?;

        packets.extend(parsed_packets);
    }

    let potential_set = Par2ParsedSet::from_packets(packets)?;

    let validated_set = potential_set.validate()?;

    let base_path = primary_file.parent().unwrap_or(Path::new("."));

    let verified_set = verify::verify_set(validated_set, base_path);

    trace!("{:#?}", verified_set);

    Ok(())
}
