use crate::error::Par2Error;
use crate::file;
use crate::packet::{Par2FileId, Par2Md5Hash, Par2RecoverySliceData};
use crate::set::Par2Set;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Par2VerifiedSet {
    pub(crate) results: Vec<Par2FileVerificationResult>,
    non_recovery_file_ids: Vec<Par2FileId>,
    recovery_file_ids: Vec<Par2FileId>,
    recovery_slices: Vec<Par2RecoverySliceData>,
    pub(crate) slice_size: u64,
}

#[derive(Debug)]
pub(crate) enum Par2FileVerificationResult {
    Found {
        file_id: Par2FileId,
        file_length: u64,
        file_md5: Par2Md5Hash,
        file_name: String,
        file_path: PathBuf,
        slices: Vec<Par2VerificationSliceStatus>,
    },
    FoundWithoutChecksums {
        file_id: Par2FileId,
        file_intact: bool,
        file_length: u64,
        file_md5: Par2Md5Hash,
        file_name: String,
        file_path: PathBuf,
    },
    NotFound {
        file_id: Par2FileId,
        file_length: u64,
        file_path: PathBuf,
    },
    Unreadable {
        error: Par2Error,
        file_id: Par2FileId,
        file_path: PathBuf,
    },
}

#[derive(Debug)]
pub(crate) enum Par2VerificationSliceStatus {
    Corrupt,
    Missing,
    Valid,
}

pub fn verify_set(set: Par2Set, base_path: &Path) -> Par2VerifiedSet {
    let mut results = Vec::new();

    for (file_id, file_description) in set.file_descriptions.into_iter() {
        // TODO Join Path::new(file_name).file_name() to strip paths
        let file_path = base_path.join(file_description.file_name);

        if !file_path.is_file() {
            results.push(Par2FileVerificationResult::NotFound {
                file_id,
                file_length: file_description.file_length,
                file_path,
            });
            continue;
        }

        let computed_checksums = match file::compute_file_checksums(&file_path, set.main.slice_size)
        {
            Ok(id) => id,
            Err(error) => {
                results.push(Par2FileVerificationResult::Unreadable {
                    error,
                    file_id,
                    file_path,
                });
                continue;
            }
        };

        let file_checksums = match set.slice_checksums.get(&file_id) {
            Some(checksum) => checksum,
            None => {
                results.push(Par2FileVerificationResult::FoundWithoutChecksums {
                    file_id,
                    file_intact: file_description.file_md5 == computed_checksums.file_md5,
                    file_length: computed_checksums.file_length,
                    file_md5: computed_checksums.file_md5,
                    file_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
                    file_path: file_path.clone(),
                });
                continue;
            }
        };

        println!("Verifying file: {} / {}", file_id, file_path.display());

        let mut slice_statuses = Vec::new();
        let expected_count = file_checksums.entries.len();
        let computed_count = computed_checksums.computed_slice_checksums.len();

        for i in 0..expected_count.min(computed_count) {
            let file_checksum = &file_checksums.entries[i];
            let computed_checksum = &computed_checksums.computed_slice_checksums[i];

            if file_checksum != computed_checksum {
                slice_statuses.push(Par2VerificationSliceStatus::Corrupt);
            } else {
                slice_statuses.push(Par2VerificationSliceStatus::Valid);
            }
        }

        for _ in computed_count..expected_count {
            slice_statuses.push(Par2VerificationSliceStatus::Missing);
        }

        results.push(Par2FileVerificationResult::Found {
            file_id,
            file_length: computed_checksums.file_length,
            file_md5: computed_checksums.file_md5,
            file_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
            file_path: file_path.clone(),
            slices: slice_statuses,
        });
    }

    Par2VerifiedSet {
        slice_size: set.main.slice_size,
        results,
        recovery_slices: set.recovery_slices,
        recovery_file_ids: set.main.recovery_file_ids,
        non_recovery_file_ids: set.main.non_recovery_file_ids,
    }
}
