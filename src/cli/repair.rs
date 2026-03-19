use crate::cli::{load_and_verify, plural};
use crate::error::Par2Error;
use crate::galois::{GaloisFieldCalculator, build_slice_constants};
use crate::packet::{Par2FileId, Par2RecoverySliceData};
use crate::verify::{
    Par2FileVerificationResult, Par2VerificationSliceStatus, Par2VerificationStatus,
    Par2VerifiedSet,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use log::{info, trace};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::ops::Mul;
use std::path::{Path, PathBuf};
use std::process::abort;
use tempfile::NamedTempFile;

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

    trace!("{:#?}", verified_set);

    let mut job = RepairJob::new(&verified_set);

    job.subtract_known_contributions()?;
    job.solve()?;
    job.write_recovered_files()?;

    todo!()
}

struct RepairJob<'a> {
    calculator: GaloisFieldCalculator,
    missing_indexes: Vec<u64>,
    recovery_buffers: Vec<Par2RecoverySliceData>,
    result_map: HashMap<Par2FileId, &'a Par2FileVerificationResult>,
    slices: Vec<SliceData>,
    valid_indexes: Vec<u64>,
    verified_set: &'a Par2VerifiedSet,
}

impl<'a> RepairJob<'a> {
    pub(crate) fn new(verified_set: &'a Par2VerifiedSet) -> Self {
        let calculator = GaloisFieldCalculator::new();

        let total_input_slices: u16 = verified_set
            .results
            .iter()
            .map(|d| d.file_length.div_ceil(verified_set.slice_size) as u16)
            .sum();

        let slice_constants = build_slice_constants(&calculator, total_input_slices);

        let result_map: HashMap<Par2FileId, &Par2FileVerificationResult> = verified_set
            .results
            .iter()
            .map(|res| (res.file_id.clone(), res))
            .collect();

        let slices = build_slices(
            &verified_set.recovery_file_ids,
            &result_map,
            &slice_constants,
            verified_set.slice_size,
        );

        let missing_indexes: Vec<_> = slices
            .iter()
            .filter(|d| d.status != Par2VerificationSliceStatus::Valid)
            .map(|d| d.global_slice_index)
            .collect();

        let valid_indexes: Vec<_> = slices
            .iter()
            .filter(|d| d.status == Par2VerificationSliceStatus::Valid)
            .map(|d| d.global_slice_index)
            .collect();

        let recovery_buffers: Vec<Par2RecoverySliceData> =
            verified_set.recovery_slices[..missing_indexes.len()].to_vec();

        trace!("Slices {:#?}", slices);
        trace!("Missing indexes {:?}", missing_indexes);
        trace!("Valid indexes {:?}", valid_indexes);

        Self {
            calculator,
            missing_indexes,
            recovery_buffers,
            result_map,
            slices,
            valid_indexes,
            verified_set,
        }
    }

    pub(crate) fn subtract_known_contributions(&mut self) -> Result<(), Par2Error> {
        for valid_index in &self.valid_indexes {
            let slice = &self.slices[*valid_index as usize];
            let file_result = &self.result_map[&slice.file_id];

            trace!(
                "Reading slice {} from {}",
                slice.local_slice_index,
                file_result.file_path.display()
            );

            let valid_file_data = read_slice_from_disk(
                &file_result.file_path,
                slice.local_slice_index,
                self.verified_set.slice_size,
            )?;

            for recovery_buffer in &mut self.recovery_buffers {
                let coefficient = self
                    .calculator
                    .power(slice.gf_constant, recovery_buffer.exponent as u16);

                for word_index in 0..recovery_buffer.recovery_data.len() / 2 {
                    let byte_index = word_index * 2;

                    let valid_word = u16::from_le_bytes([
                        valid_file_data[byte_index],
                        valid_file_data[byte_index + 1],
                    ]);

                    let mut recovery_word = u16::from_le_bytes([
                        recovery_buffer.recovery_data[byte_index],
                        recovery_buffer.recovery_data[byte_index + 1],
                    ]);

                    recovery_word ^= self.calculator.multiply(coefficient, valid_word);

                    recovery_buffer.recovery_data[byte_index..byte_index + 2]
                        .copy_from_slice(&recovery_word.to_le_bytes());
                }
            }
        }

        Ok(())
    }

    pub(crate) fn solve(&mut self) -> Result<(), Par2Error> {
        let k = self.missing_indexes.len();
        let mut matrix = vec![vec![0u16; k]; k];

        for row in 0..k {
            let exponent = self.recovery_buffers[row].exponent as u16;
            for col in 0..k {
                let constant = self.slices[self.missing_indexes[col as usize] as usize].gf_constant;

                matrix[row][col] = self.calculator.power(constant, exponent);
            }
        }

        for col in 0..k {
            let mut diagonal = matrix[col][col];

            if diagonal == 0 {
                for row in col + 1..k {
                    let new_diagonal = matrix[row][col];

                    if new_diagonal != 0 {
                        matrix.swap(row, col);
                        self.recovery_buffers.swap(row, col);

                        // Break out of the inner loop
                        break;
                    }
                }

                // Update diagonal after swap
                diagonal = matrix[col][col];
            }

            // Scale the matrix row
            for entry in 0..k {
                matrix[col][entry] = self.calculator.divide(matrix[col][entry], diagonal)?;
            }

            // Scale the corresponding recovery buffer by the same amount
            let inverse = self.calculator.inverse(diagonal)?;
            for word_index in 0..(self.verified_set.slice_size / 2) {
                let byte_index = word_index as usize * 2;

                let recovery_word = u16::from_le_bytes([
                    self.recovery_buffers[col].recovery_data[byte_index],
                    self.recovery_buffers[col].recovery_data[byte_index + 1],
                ]);

                let updated_word = self.calculator.multiply(recovery_word, inverse);

                self.recovery_buffers[col].recovery_data[byte_index..byte_index + 2]
                    .copy_from_slice(&updated_word.to_le_bytes());
            }

            for row in 0..k {
                if row == col {
                    continue;
                }

                let factor = matrix[row][col];

                if factor == 0 {
                    continue;
                }

                // Eliminate in the matrix
                for entry in 0..k {
                    matrix[row][entry] ^= self.calculator.multiply(factor, matrix[col][entry]);
                }

                // Eliminate in the recovery data
                for word_index in 0..(self.verified_set.slice_size / 2) {
                    let byte_index = word_index as usize * 2;

                    let pivot_word = u16::from_le_bytes([
                        self.recovery_buffers[col].recovery_data[byte_index],
                        self.recovery_buffers[col].recovery_data[byte_index + 1],
                    ]);

                    let mut target_word = u16::from_le_bytes([
                        self.recovery_buffers[row].recovery_data[byte_index],
                        self.recovery_buffers[row].recovery_data[byte_index + 1],
                    ]);

                    target_word ^= self.calculator.multiply(factor, pivot_word);

                    self.recovery_buffers[row].recovery_data[byte_index..byte_index + 2]
                        .copy_from_slice(&target_word.to_le_bytes());
                }
            }
        }

        Ok(())
    }

    pub(crate) fn write_recovered_files(&self) -> Result<(), Par2Error> {
        for result in &self.verified_set.results {
            match &result.status {
                Par2VerificationStatus::Unreadable { error } => {
                    // fail(?)
                }
                Par2VerificationStatus::NotFound => {
                    // write all repaired slices
                }
                Par2VerificationStatus::Found { slices, .. } => {
                    // write valid slices mixed with repaired slices
                }
            }
        }

        todo!()
    }
}

fn read_slice_from_disk(
    file_path: &Path,
    slice_index: u64,
    slice_size: u64,
) -> Result<Vec<u8>, Par2Error> {
    let file = File::open(file_path)?;

    let start_position = slice_size * slice_index;
    let mut slice_buffer = vec![0u8; slice_size as usize];
    let mut reader = BufReader::new(file);

    reader.seek(SeekFrom::Start(start_position))?;

    let mut bytes_read = 0;
    while bytes_read < slice_buffer.len() {
        match reader.read(&mut slice_buffer[bytes_read..])? {
            0 => break,
            current_read => bytes_read += current_read,
        }
    }

    Ok(slice_buffer)
}

#[derive(Debug)]
struct SliceData {
    file_id: Par2FileId,
    gf_constant: u16,
    global_slice_index: u64,
    local_slice_index: u64,
    status: Par2VerificationSliceStatus,
}

fn build_slices(
    recovery_file_ids: &[Par2FileId],
    result_map: &HashMap<Par2FileId, &Par2FileVerificationResult>,
    slice_constants: &[u16],
    slice_size: u64,
) -> Vec<SliceData> {
    let mut slice_map: Vec<SliceData> = Vec::new();
    let mut global_slice_index = 0;

    for recovery_file_id in recovery_file_ids {
        let Some(result) = result_map.get(recovery_file_id) else {
            continue;
        };

        match &result.status {
            Par2VerificationStatus::Found { slices, .. } => {
                let mut local_slice_index = 0;

                for slice in slices {
                    slice_map.push(SliceData {
                        file_id: recovery_file_id.clone(),
                        gf_constant: slice_constants[global_slice_index as usize],
                        global_slice_index,
                        local_slice_index,
                        status: slice.clone(),
                    });

                    global_slice_index += 1;
                    local_slice_index += 1;
                }
                continue;
            }
            Par2VerificationStatus::NotFound => {
                let file_slice_count = result.file_length.div_ceil(slice_size);

                for local_slice_index in 0..file_slice_count {
                    slice_map.push(SliceData {
                        file_id: recovery_file_id.clone(),
                        gf_constant: slice_constants[global_slice_index as usize],
                        global_slice_index,
                        local_slice_index,
                        status: Par2VerificationSliceStatus::Missing,
                    });

                    global_slice_index += 1;
                }
                continue;
            }
            Par2VerificationStatus::Unreadable { .. } => {
                // TODO ?
                continue;
            }
        }
    }

    slice_map
}
