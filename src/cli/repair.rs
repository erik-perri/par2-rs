use crate::cli::load_and_verify;
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
