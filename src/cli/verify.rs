use crate::cli::load_and_verify;
use crate::error::Par2Error;
use crate::verify::{Par2VerificationSliceStatus, Par2VerificationStatus};
use colored::Colorize;
use log::info;
use std::path::Path;

pub(crate) fn verify(path: &Path) -> Result<(), Par2Error> {
    let verified_set = load_and_verify(path)?;

    info!("Verifying files:");

    for result in &verified_set.results {
        let file_name = result.file_name.bold();

        match &result.status {
            Par2VerificationStatus::Found {
                computed_md5,
                slices,
            } => {
                if computed_md5 == &result.expected_md5 {
                    info!("- Target: {} - {}", file_name, "found".green());
                } else if slices.is_empty() {
                    info!(
                        "- Target: {} - {} (no block checksums available)",
                        file_name,
                        "damaged".red()
                    );
                } else {
                    let valid = slices
                        .iter()
                        .filter(|s| matches!(s, Par2VerificationSliceStatus::Valid))
                        .count();

                    info!(
                        "- Target: {} - {}. Found {} of {} data blocks",
                        file_name,
                        "damaged".red(),
                        valid,
                        slices.len(),
                    );
                }
            }
            Par2VerificationStatus::NotFound => {
                info!("- Target: {} - {}", file_name, "missing".red());
            }
            Par2VerificationStatus::Unreadable { error } => {
                info!(
                    "- Target: {} - {} {}",
                    file_name,
                    "unreadable".red(),
                    error.to_string().dimmed()
                );
            }
        }
    }

    info!("");

    if verified_set.is_all_intact() {
        info!("{}", "Repair not required.".green().bold());
        return Ok(());
    }

    info!("Repair is required.");

    let damaged = verified_set.damaged_count();
    if damaged > 0 {
        info!("{} file(s) exist but are damaged.", damaged);
    }

    let missing = verified_set.missing_count();
    if missing > 0 {
        info!("{} file(s) are missing.", missing);
    }

    let available: usize = verified_set.available_blocks();
    info!(
        "You have {} out of {} data blocks available.",
        available, verified_set.total_data_blocks
    );

    let recovery = verified_set.recovery_slices.len();
    info!("You have {} recovery blocks available.", recovery);

    let missing = verified_set.total_data_blocks - available;

    if recovery > missing {
        let extra = recovery - missing;
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
                missing - recovery
            )
            .red()
            .bold(),
        );
    }

    Err(Par2Error::RepairRequired)
}
