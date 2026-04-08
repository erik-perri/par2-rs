use crate::cli::{load_and_verify, plural};
use crate::error::Par2Error;
use crate::galois::{GaloisFieldCalculator, build_slice_constants};
use crate::packet::{Par2FileId, Par2RecoverySliceData};
use crate::verify::{
    Par2FileVerificationResult, Par2VerificationSliceStatus, Par2VerificationStatus,
    Par2VerifiedSet,
};
use colored::Colorize;
use log::{debug, info, trace};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) fn repair(path: &Path) -> Result<(), Par2Error> {
    let verified_set = load_and_verify(path)?;

    if verified_set.is_all_intact() {
        info!("{}", "Repair not required.".yellow().bold());
        return Ok(());
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

    if missing_block_count > 0 {
        info!(
            "Repairing {} missing {} using {} recovery {}.",
            missing_block_count,
            plural(missing_block_count, "block", "blocks"),
            recovery_block_count,
            plural(recovery_block_count, "block", "blocks"),
        );
    } else {
        info!("Repairing damaged files...");
    }

    info!("");

    trace!("{:#?}", verified_set);

    let mut job = RepairJob::new(&verified_set);

    job.run()?;

    info!("");
    info!("{}", "Repair complete.".green().bold());

    Ok(())
}

struct RepairJob<'a> {
    calculator: GaloisFieldCalculator,
    missing_indexes: Vec<usize>,
    recovery_buffers: Vec<Par2RecoverySliceData>,
    result_map: HashMap<Par2FileId, &'a Par2FileVerificationResult>,
    slices: Vec<SliceData>,
    valid_indexes: Vec<usize>,
    verified_set: &'a Par2VerifiedSet,
}

#[derive(Debug)]
enum SliceSource {
    Original { local_slice_index: usize },
    Recovered { recovery_buffer_index: usize },
}

#[derive(Debug)]
struct RepairPlan {
    file_path: PathBuf,
    file_length: u64,
    slices: Vec<SliceSource>,
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

    pub(crate) fn run(&mut self) -> Result<(), Par2Error> {
        self.subtract_known_contributions()?;
        self.solve()?;
        let plan = self.plan()?;

        trace!("Plan {:#?}", plan);

        self.write_recovered_files(plan)?;

        Ok(())
    }

    fn plan(&mut self) -> Result<Vec<RepairPlan>, Par2Error> {
        let mut plan = Vec::new();

        for file_id in &self.verified_set.recovery_file_ids {
            let result = self.result_map.get(file_id).ok_or_else(|| {
                Par2Error::FilePathError("unable to find file description".into())
            })?;

            if let Par2VerificationStatus::Found { computed_md5, .. } = &result.status {
                if result.expected_md5 == *computed_md5 {
                    continue;
                }
            }

            let mut slices = Vec::new();

            for global_slice_index in
                result.global_slice_start..result.global_slice_start + result.slice_count
            {
                let slice_result = self
                    .slices
                    .get(global_slice_index)
                    .ok_or_else(|| Par2Error::RepairError("unable to find slice result".into()))?;

                match slice_result.status {
                    Par2VerificationSliceStatus::Valid => slices.push(SliceSource::Original {
                        local_slice_index: global_slice_index - result.global_slice_start,
                    }),
                    Par2VerificationSliceStatus::Missing | Par2VerificationSliceStatus::Corrupt => {
                        let recovery_buffer_index = self
                            .missing_indexes
                            .iter()
                            .position(|&index| index == global_slice_index)
                            .ok_or_else(|| {
                                Par2Error::RepairError("unable to find recovery index".into())
                            })?;

                        slices.push(SliceSource::Recovered {
                            recovery_buffer_index,
                        })
                    }
                }
            }

            plan.push(RepairPlan {
                file_length: result.file_length,
                file_path: result.file_path.clone(),
                slices,
            })
        }

        Ok(plan)
    }

    fn subtract_known_contributions(&mut self) -> Result<(), Par2Error> {
        info!("Subtracting known data contributions...");

        for (i, valid_index) in self.valid_indexes.iter().enumerate() {
            let slice = &self.slices[*valid_index as usize];
            let file_result = &self.result_map[&slice.file_id];

            debug!(
                "Processing data block {} of {} from {}",
                i + 1,
                self.valid_indexes.len(),
                file_result
                    .file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .bold(),
            );

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

    fn solve(&mut self) -> Result<(), Par2Error> {
        info!("Computing repair data...");

        let k = self.missing_indexes.len();
        let mut matrix = vec![vec![0u16; k]; k];

        for row in 0..k {
            let exponent = self.recovery_buffers[row].exponent as u16;
            for col in 0..k {
                let constant = self.slices[self.missing_indexes[col] as usize].gf_constant;

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

    fn write_recovered_files(&self, plan: Vec<RepairPlan>) -> Result<(), Par2Error> {
        info!("Writing repaired files...");

        for file_plan in plan {
            info!(
                "- Writing {}",
                file_plan
                    .file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .bold(),
            );

            let temp_path = get_temp_path(&file_plan.file_path)?;
            let mut file = File::create(&temp_path)?;

            for slice in file_plan.slices {
                match slice {
                    SliceSource::Original { local_slice_index } => {
                        let bytes = read_slice_from_disk(
                            &file_plan.file_path,
                            local_slice_index,
                            self.verified_set.slice_size,
                        )?;

                        file.write_all(&bytes)?;
                    }
                    SliceSource::Recovered {
                        recovery_buffer_index,
                    } => {
                        let recovery_result = self
                            .recovery_buffers
                            .get(recovery_buffer_index)
                            .ok_or_else(|| {
                                Par2Error::RepairError("unable to find recovery data".into())
                            })?;

                        file.write_all(&recovery_result.recovery_data)?;
                    }
                }
            }

            file.set_len(file_plan.file_length)?;
            std::fs::rename(&temp_path, &file_plan.file_path)?
        }

        Ok(())
    }
}

fn read_slice_from_disk(
    file_path: &Path,
    slice_index: usize,
    slice_size: u64,
) -> Result<Vec<u8>, Par2Error> {
    let file = File::open(file_path)?;

    let start_position = slice_size * slice_index as u64;
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
    global_slice_index: usize,
    local_slice_index: usize,
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
            Par2VerificationStatus::NotFound | Par2VerificationStatus::Unreadable { .. } => {
                let file_slice_count = result.file_length.div_ceil(slice_size) as usize;

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
        }
    }

    slice_map
}

fn get_temp_path(file_path: &PathBuf) -> Result<PathBuf, Par2Error> {
    let file_name = file_path
        .file_name()
        .ok_or_else(|| Par2Error::FilePathError("unable to determine file name".into()))?;
    let parent_path = file_path
        .parent()
        .ok_or_else(|| Par2Error::FilePathError("file path is missing parent".into()))?;

    for i in 1..10 {
        let potentially_unique_path = parent_path.join(format!("{}.{}", file_name.display(), i));

        if !potentially_unique_path.exists() {
            return Ok(potentially_unique_path);
        }
    }

    Err(Par2Error::FilePathError(
        "Unable to create output file".to_string(),
    ))
}
