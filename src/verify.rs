use crate::packet::{Par2FileId, Par2Md5Hash, Par2RecoverySliceData, Par2SliceChecksumEntry};
use crate::set::Par2ValidatedSet;
use byteorder::{LittleEndian, WriteBytesExt};
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Par2VerifiedSet {
    results: Vec<Par2FileVerificationResult>,
    non_recovery_file_ids: Vec<Par2FileId>,
    recovery_file_ids: Vec<Par2FileId>,
    recovery_slices: Vec<Par2RecoverySliceData>,
    slice_size: u64,
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
        error: String,
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

pub fn verify_set(set: Par2ValidatedSet, base_path: &Path) -> Par2VerifiedSet {
    let mut results = Vec::new();

    for file_description in set.file_descriptions.into_values() {
        // TODO Join Path::new(file_name).file_name() to strip paths
        let file_path = base_path.join(file_description.file_name);

        if !file_path.is_file() {
            results.push(Par2FileVerificationResult::NotFound {
                file_id: file_description.file_id,
                file_length: file_description.file_length,
                file_path,
            });
            continue;
        }

        let computed_checksums = match compute_file_checksums(&file_path, set.main.slice_size) {
            Ok(id) => id,
            Err(error) => {
                results.push(Par2FileVerificationResult::Unreadable {
                    error,
                    file_id: file_description.file_id,
                    file_path,
                });
                continue;
            }
        };

        let file_checksums = match set.slice_checksums.get(&file_description.file_id) {
            Some(checksum) => checksum,
            None => {
                results.push(Par2FileVerificationResult::FoundWithoutChecksums {
                    file_id: file_description.file_id,
                    file_intact: file_description.file_md5 == computed_checksums.file_md5,
                    file_length: computed_checksums.file_length,
                    file_md5: computed_checksums.file_md5,
                    file_name: file_path.file_name().unwrap().to_string_lossy().to_string(),
                    file_path: file_path.clone(),
                });
                continue;
            }
        };

        println!(
            "Verifying file: {} / {}",
            file_description.file_id,
            file_path.display()
        );

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
            file_id: file_description.file_id,
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

struct Par2FileChecksums {
    computed_slice_checksums: Vec<Par2SliceChecksumEntry>,
    file_id: Par2FileId,
    file_length: u64,
    file_md5: Par2Md5Hash,
}

fn compute_file_checksums(file_path: &Path, slice_size: u64) -> Result<Par2FileChecksums, String> {
    let file_metadata = file_path
        .metadata()
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;

    let file_name = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "File path is missing or contains invalid UTF-8".to_string())?;

    let file_length = file_metadata.len();
    let file = File::open(file_path).map_err(|e| format!("Failed to open file: {}", e))?;

    let first_16kb_size = (16 * 1024).min(file_length);

    let mut reader = BufReader::new(file);
    let mut slice_buffer = vec![0u8; slice_size as usize];
    let mut first_16kb_buffer = vec![0u8; first_16kb_size as usize];

    reader
        .read_exact(&mut first_16kb_buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("Failed to seek file: {}", e))?;

    let first_16kb_md5 = Par2Md5Hash(Md5::digest(&first_16kb_buffer).into());

    let mut file_md5_hasher = Md5::new();
    let mut computed_slice_checksums = Vec::new();

    loop {
        slice_buffer.clear();

        let read_length = (&mut reader)
            .take(slice_size)
            .read_to_end(&mut slice_buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        if read_length == 0 {
            break;
        }

        file_md5_hasher.update(&slice_buffer[..read_length]);

        let mut slice_md5_hasher = Md5::new();
        let mut slice_crc32_hasher = crc32fast::Hasher::new();

        let padding_length = (slice_size - (read_length as u64)) % slice_size;
        let padding_buffer = vec![0; padding_length as usize];

        slice_md5_hasher.update(&slice_buffer[..read_length]);
        slice_md5_hasher.update(&padding_buffer);

        slice_crc32_hasher.update(&slice_buffer[..read_length]);
        slice_crc32_hasher.update(&padding_buffer);

        let slice_md5 = Par2Md5Hash(slice_md5_hasher.finalize().into());
        let slice_crc32 = slice_crc32_hasher.finalize();

        computed_slice_checksums.push(Par2SliceChecksumEntry {
            md5: slice_md5,
            crc32: slice_crc32,
        })
    }

    let file_md5 = Par2Md5Hash(file_md5_hasher.finalize().into());
    let file_id = compute_file_id(file_name, file_length, &first_16kb_md5);

    Ok(Par2FileChecksums {
        computed_slice_checksums,
        file_id,
        file_length,
        file_md5,
    })
}

fn compute_file_id(file_name: &str, file_length: u64, first_16kb_md5: &Par2Md5Hash) -> Par2FileId {
    let mut buffer = Vec::new();

    buffer.extend_from_slice(first_16kb_md5.as_ref());
    buffer.write_u64::<LittleEndian>(file_length).unwrap();
    buffer.extend_from_slice(file_name.as_bytes());

    let computed_file_id = Par2Md5Hash(Md5::digest(&buffer).into());

    Par2FileId::from(computed_file_id)
}
