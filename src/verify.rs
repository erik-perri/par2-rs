use crate::error::Par2Error;
use crate::file;
use crate::packet::{Par2FileId, Par2Md5Hash, Par2RecoverySliceData};
use crate::set::Par2Set;
use log::debug;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Par2VerifiedSet {
    pub(crate) results: Vec<Par2FileVerificationResult>,
    pub(crate) non_recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_slices: Vec<Par2RecoverySliceData>,
    pub(crate) slice_size: u64,
}

#[derive(Debug)]
pub(crate) enum Par2VerificationSliceStatus {
    Corrupt,
    Missing,
    Valid,
}

#[derive(Debug)]
pub(crate) enum Par2VerificationStatus {
    Found {
        computed_md5: Par2Md5Hash,
        slices: Vec<Par2VerificationSliceStatus>,
    },
    NotFound,
    Unreadable {
        error: Par2Error,
    },
}

#[derive(Debug)]
pub(crate) struct Par2FileVerificationResult {
    pub(crate) expected_md5: Par2Md5Hash,
    pub(crate) file_id: Par2FileId,
    pub(crate) file_length: u64,
    pub(crate) file_name: String,
    pub(crate) file_path: PathBuf,
    pub(crate) status: Par2VerificationStatus,
}

pub(crate) fn verify_set(set: Par2Set, base_path: &Path) -> Par2VerifiedSet {
    let mut results = Vec::new();

    for (file_id, file_description) in set.file_descriptions.into_iter() {
        // TODO Join Path::new(file_name).file_name() to strip paths
        let file_path = base_path.join(file_description.file_name);
        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();

        if !file_path.is_file() {
            results.push(Par2FileVerificationResult {
                expected_md5: file_description.file_md5,
                file_id,
                file_length: file_description.file_length,
                file_name,
                file_path,
                status: Par2VerificationStatus::NotFound,
            });
            continue;
        }

        let computed_checksums = match file::compute_file_data(&file_path, set.main.slice_size) {
            Ok(id) => id,
            Err(error) => {
                results.push(Par2FileVerificationResult {
                    expected_md5: file_description.file_md5,
                    file_id,
                    file_length: file_description.file_length,
                    file_name,
                    file_path,
                    status: Par2VerificationStatus::Unreadable { error },
                });
                continue;
            }
        };

        let file_checksums = match set.slice_checksums.get(&file_id) {
            Some(checksum) => checksum,
            None => {
                results.push(Par2FileVerificationResult {
                    expected_md5: file_description.file_md5,
                    file_id,
                    file_length: computed_checksums.file_length,
                    file_name,
                    file_path: file_path.clone(),
                    status: Par2VerificationStatus::Found {
                        computed_md5: computed_checksums.file_md5,
                        slices: vec![],
                    },
                });
                continue;
            }
        };

        debug!("Verifying file: {} / {}", file_id, file_path.display());

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

        results.push(Par2FileVerificationResult {
            expected_md5: file_description.file_md5,
            file_id,
            file_length: computed_checksums.file_length,
            file_name,
            file_path: file_path.clone(),
            status: Par2VerificationStatus::Found {
                computed_md5: computed_checksums.file_md5,
                slices: slice_statuses,
            },
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
