use crate::error::Par2Error;
use crate::packet::PAR2_PACKET_MAGIC_RECOVERY_SLICE;
use crate::set::Par2ParsedSet;
use crate::verify::Par2FileVerificationResult;
use crate::{file, packet, verify};
use colored::Colorize;
use log::{debug, info, trace, warn};
use std::fs;
use std::path::Path;

pub(crate) fn verify(path: &Path) -> Result<(), Par2Error> {
    let primary_file = fs::canonicalize(path)?;

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

    let potential_set = Par2ParsedSet::from_packets(packets)?;

    let validated_set = potential_set.validate()?;

    let creator = validated_set.creators.first().map(|c| c.name.clone());
    let recoverable_files = validated_set.main.recovery_file_ids.len();
    let other_files = validated_set.main.non_recovery_file_ids.len();
    let block_size = validated_set.main.slice_size;
    let total_data_blocks: usize = validated_set
        .slice_checksums
        .values()
        .map(|sc| sc.entries.len())
        .sum();
    let total_file_size: u64 = validated_set
        .file_descriptions
        .values()
        .map(|fd| fd.file_length)
        .sum();

    info!("");
    if let Some(name) = &creator {
        info!("Creator: {}", name.bold());
    }

    if !validated_set.warnings.is_empty() {
        warn!("{}", "Warnings:".yellow());
        for warning in &validated_set.warnings {
            warn!("- {}", warning);
        }
    }

    info!("Recoverable files: {}", recoverable_files);
    info!("Other files: {}", other_files);
    info!("Total size: {} bytes", total_file_size);
    debug!("Block size: {} bytes", block_size);
    debug!("Data blocks: {}", total_data_blocks);

    let base_path = primary_file.parent().unwrap_or(Path::new("."));

    let verified_set = verify::verify_set(validated_set, base_path);

    trace!("{:#?}", verified_set);

    info!("");
    info!("Verifying files:");

    for result in &verified_set.results {
        match result {
            Par2FileVerificationResult::Found {
                file_name, slices, ..
            } => {
                if result.is_intact() {
                    info!(
                        "- Target: {} - {}",
                        file_name.to_string().bold(),
                        "found".green()
                    );
                } else {
                    let found_slices = result.found_slices();
                    if found_slices > 0 {
                        let valid = result.valid_slices();
                        let total = slices.len();
                        info!(
                            "- Target: {} - {}. Found {} of {} data blocks",
                            file_name.to_string().bold(),
                            "damaged".red(),
                            valid,
                            total
                        );
                    } else {
                        info!(
                            "- Target: {} - {} (no block checksums available)",
                            file_name.to_string().bold(),
                            "damaged".red()
                        );
                    }
                }
            }
            Par2FileVerificationResult::NotFound { file_path, .. } => {
                let name = file_path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                info!("- Target: {} - {}", name.bold(), "missing".red());
            }
            Par2FileVerificationResult::Unreadable { file_path, .. } => {
                let name = file_path
                    .file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default();
                info!("- Target: {} - {}", name.bold(), "unreadable".red());
            }
        }
    }

    info!("");

    if verified_set.is_all_intact() {
        info!("{}", "Repair not required.".green().bold());
        return Ok(());
    }

    info!("Repair is required.");

    let damaged = verified_set.damaged_file_count();
    if damaged > 0 {
        info!("{} file(s) exist but are damaged.", damaged);
    }

    let missing = verified_set.missing_file_count();
    if missing > 0 {
        info!("{} file(s) are missing.", missing);
    }

    let available = verified_set.available_data_blocks();
    info!(
        "You have {} out of {} data blocks available.",
        available, total_data_blocks
    );

    let recovery = verified_set.recovery_blocks_available();
    info!("You have {} recovery blocks available.", recovery);

    if verified_set.is_repair_possible() {
        let extra = recovery - verified_set.missing_blocks();
        if extra > 0 {
            info!(
                "{}",
                format!("Repair is possible, {} extra recovery blocks.", extra)
                    .yellow()
                    .bold()
            );
        } else {
            info!(
                "{}",
                "Repair is possible with no blocks to spare."
                    .yellow()
                    .bold()
            );
        }
    } else {
        info!(
            "{}",
            format!(
                "You need {} more recovery blocks for repair.",
                verified_set.missing_blocks() - recovery
            )
            .red()
            .bold(),
        );
    }

    Err(Par2Error::RepairRequired)
}
