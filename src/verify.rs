use crate::error::{Par2Error, Par2Warning};
use crate::file;
use crate::file_name::get_sanitized_file_path;
use crate::packet::{Par2FileId, Par2Md5Hash, Par2RecoverySliceData};
use crate::set::Par2Set;
use log::debug;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Par2VerifiedSet {
    pub(crate) creator: Option<String>,
    pub(crate) non_recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_slices: Vec<Par2RecoverySliceData>,
    pub(crate) results: Vec<Par2FileVerificationResult>,
    pub(crate) slice_size: u64,
    pub(crate) total_data_blocks: usize,
    pub(crate) total_file_size: u64,
    pub(crate) warnings: Vec<Par2Warning>,
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

impl Par2VerifiedSet {
    pub(crate) fn from_set(set: Par2Set, base_path: &Path) -> Result<Self, Par2Error> {
        let mut results = Vec::new();

        let total_data_blocks = set.total_data_blocks();
        let total_file_size = set.total_file_size();

        for (file_id, file_description) in set.file_descriptions.into_iter() {
            let file_path = get_sanitized_file_path(base_path, &file_description.file_name)?;
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

            let computed_checksums = match file::compute_file_data(&file_path, set.main.slice_size)
            {
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

        let creator = if set.creators.is_empty() {
            None
        } else {
            Some(
                set.creators
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        };

        Ok(Self {
            creator,
            non_recovery_file_ids: set.main.non_recovery_file_ids,
            recovery_file_ids: set.main.recovery_file_ids,
            recovery_slices: set.recovery_slices,
            results,
            slice_size: set.main.slice_size,
            total_data_blocks,
            total_file_size,
            warnings: set.warnings,
        })
    }

    pub(crate) fn available_blocks(&self) -> usize {
        self.results
            .iter()
            .map(|r| match &r.status {
                Par2VerificationStatus::Found { slices, .. } => slices
                    .iter()
                    .filter(|s| matches!(s, Par2VerificationSliceStatus::Valid))
                    .count(),
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn damaged_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| match &r.status {
                Par2VerificationStatus::Found { computed_md5, .. } => {
                    computed_md5 != &r.expected_md5
                }
                _ => false,
            })
            .count()
    }

    pub(crate) fn is_all_intact(&self) -> bool {
        self.results.iter().all(|r| match &r.status {
            Par2VerificationStatus::Found { computed_md5, .. } => computed_md5 == &r.expected_md5,
            _ => false,
        })
    }

    pub(crate) fn missing_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.status, Par2VerificationStatus::NotFound))
            .count()
    }
}
