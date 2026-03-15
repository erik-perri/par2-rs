use crate::error::Par2Error;
use crate::packet::PAR2_PACKET_MAGIC_RECOVERY_SLICE;
use crate::set::{Par2ParsedSet, Par2Set};
use crate::verify::{Par2VerificationStatus, Par2VerifiedSet};
use crate::{file, packet};
use colored::Colorize;
use log::{debug, info, warn};
use std::fs;
use std::path::Path;

pub(crate) fn repair(path: &Path) -> Result<(), Par2Error> {
    let primary_file = fs::canonicalize(path)?;
    let base_path = primary_file.parent().unwrap_or(Path::new("."));
    let file_paths = file::locate_files(&primary_file)?;

    let mut packets = Vec::new();

    for file_path in file_paths {
        info!(
            "Loading: {}",
            file_path
                .file_name()
                .ok_or(Par2Error::ParseError(
                    "failed to read file name".to_string()
                ))?
                .to_string_lossy()
                .bold()
        );

        let parsed_packets = packet::parse_file(&file_path)?;

        let recovery_blocks = parsed_packets
            .iter()
            .filter(|b| b.body.packet_type() == PAR2_PACKET_MAGIC_RECOVERY_SLICE)
            .count();

        if recovery_blocks > 0 {
            info!(
                "Loaded {} packets with {} recovery blocks",
                parsed_packets.len(),
                recovery_blocks
            );
        } else {
            info!("Loaded {} packets", parsed_packets.len());
        }

        packets.extend(parsed_packets);
    }

    let parsed_set = Par2ParsedSet::from_packets(packets)?;
    let validated_set = Par2Set::from_parsed(parsed_set)?;
    let verified_set = Par2VerifiedSet::from_set(validated_set, base_path)?;

    info!("");
    if let Some(name) = &verified_set.creator {
        info!("Creator: {}", name.bold());
    }

    if !verified_set.warnings.is_empty() {
        warn!("{}", "Warnings:".yellow());
        for warning in &verified_set.warnings {
            warn!("- {}", warning);
        }
    }

    info!(
        "Recoverable files: {}",
        verified_set.recovery_file_ids.len()
    );
    info!("Other files: {}", verified_set.non_recovery_file_ids.len());
    info!("Total size: {} bytes", verified_set.total_file_size);
    debug!("Block size: {} bytes", verified_set.slice_size);
    debug!("Data blocks: {}", verified_set.total_data_blocks);

    info!("");

    if verified_set.is_all_intact() {
        info!("{}", "Repair not required.".yellow().bold());
        return Ok(());
    }

    let recovery = verified_set.recovery_slices.len();
    let missing = verified_set.total_data_blocks - verified_set.available_blocks();

    if missing > recovery {
        info!(
            "You need {} more recovery blocks for repair.",
            missing - recovery,
        );

        info!("{}", "Repair not possible.".red().bold());
        return Err(Par2Error::RepairRequired);
    }

    for result in &verified_set.results {
        if matches!(result.status, Par2VerificationStatus::Unreadable { .. }) {
            info!(
                "File {} is unreadable, unable to repair.",
                result.file_path.display().to_string().bold()
            );
            return Err(Par2Error::RepairRequired);
        }
    }

    info!("Starting repair...");

    Err(Par2Error::ParseError("not implemented".to_string()))
}
