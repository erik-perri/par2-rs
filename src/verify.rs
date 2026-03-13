use crate::error::Par2Error;
use crate::file;
use crate::packet::{Par2FileId, Par2Md5Hash, Par2RecoverySliceData};
use crate::set::Par2Set;
use log::debug;
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
        computed_md5: Par2Md5Hash,
        expected_md5: Par2Md5Hash,
        file_id: Par2FileId,
        file_length: u64,
        file_name: String,
        file_path: PathBuf,
        slices: Vec<Par2VerificationSliceStatus>,
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

impl Par2VerifiedSet {
    pub(crate) fn total_data_blocks(&self) -> usize {
        self.results.iter().map(|r| r.found_slices()).sum()
    }

    pub(crate) fn available_data_blocks(&self) -> usize {
        self.results.iter().map(|r| r.valid_slices()).sum()
    }

    pub(crate) fn recovery_blocks_available(&self) -> usize {
        self.recovery_slices.len()
    }

    pub(crate) fn missing_blocks(&self) -> usize {
        self.total_data_blocks() - self.available_data_blocks()
    }

    pub(crate) fn is_all_intact(&self) -> bool {
        self.results.iter().all(|r| r.is_intact())
    }

    pub(crate) fn is_repair_possible(&self) -> bool {
        self.missing_blocks() <= self.recovery_blocks_available()
    }

    pub(crate) fn damaged_file_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_damaged()).count()
    }

    pub(crate) fn missing_file_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r, Par2FileVerificationResult::NotFound { .. }))
            .count()
    }
}

impl Par2FileVerificationResult {
    pub(crate) fn file_path(&self) -> &PathBuf {
        match self {
            Par2FileVerificationResult::Found { file_path, .. } => file_path,
            Par2FileVerificationResult::NotFound { file_path, .. } => file_path,
            Par2FileVerificationResult::Unreadable { file_path, .. } => file_path,
        }
    }

    pub(crate) fn found_slices(&self) -> usize {
        match self {
            Par2FileVerificationResult::Found { slices, .. } => slices.len(),
            _ => 0,
        }
    }

    pub(crate) fn valid_slices(&self) -> usize {
        match self {
            Par2FileVerificationResult::Found { slices, .. } => slices
                .iter()
                .filter(|s| matches!(s, Par2VerificationSliceStatus::Valid))
                .count(),
            _ => 0,
        }
    }

    pub(crate) fn is_intact(&self) -> bool {
        match self {
            Par2FileVerificationResult::Found {
                computed_md5,
                expected_md5,
                ..
            } => computed_md5 == expected_md5,
            _ => false,
        }
    }

    pub(crate) fn is_damaged(&self) -> bool {
        match self {
            Par2FileVerificationResult::Found {
                computed_md5,
                expected_md5,
                ..
            } => computed_md5 != expected_md5,
            Par2FileVerificationResult::Unreadable { .. } => true,
            _ => false,
        }
    }

    pub(crate) fn is_unreadable(&self) -> bool {
        match self {
            Par2FileVerificationResult::Unreadable { .. } => true,
            _ => false,
        }
    }
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

        let computed_checksums = match file::compute_file_data(&file_path, set.main.slice_size) {
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
                results.push(Par2FileVerificationResult::Found {
                    computed_md5: computed_checksums.file_md5,
                    expected_md5: file_description.file_md5,
                    file_id,
                    file_length: computed_checksums.file_length,
                    file_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
                    file_path: file_path.clone(),
                    slices: vec![],
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

        results.push(Par2FileVerificationResult::Found {
            computed_md5: computed_checksums.file_md5,
            expected_md5: file_description.file_md5,
            file_id,
            file_length: computed_checksums.file_length,
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
