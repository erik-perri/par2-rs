use crate::cli::{load_and_verify, plural};
use crate::error::Par2Error;
use crate::verify::Par2VerificationStatus;
use colored::Colorize;
use log::info;
use std::path::Path;

pub(crate) fn repair(path: &Path) -> Result<(), Par2Error> {
    let verified_set = load_and_verify(path)?;

    if verified_set.is_all_intact() {
        info!("{}", "Repair not required.".yellow().bold());
        return Ok(());
    }

    for result in &verified_set.results {
        if matches!(result.status, Par2VerificationStatus::Unreadable { .. }) {
            info!(
                "File {} is unreadable, unable to repair.",
                result.file_path.display().to_string().bold()
            );

            info!("{}", "Repair not possible.".red().bold());
            return Err(Par2Error::RepairRequired);
        }
    }

    let recovery_block_count = verified_set.recovery_slices.len();
    let missing_block_count = verified_set.total_data_blocks - verified_set.available_blocks();

    if missing_block_count > recovery_block_count {
        let needed = missing_block_count - recovery_block_count;
        info!(
            "You need {} more recovery {} for repair.",
            needed,
            plural(needed, "block", "blocks"),
        );

        info!("{}", "Repair not possible.".red().bold());
        return Err(Par2Error::RepairNotPossible);
    }

    info!("Starting repair...");

    Err(Par2Error::ParseError("not implemented".to_string()))
}
