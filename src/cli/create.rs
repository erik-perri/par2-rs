use crate::error::Par2Error;
use crate::file::{Par2ComputedFileData, compute_file_data};
use crate::file_name::plan_recovery_files;
use crate::galois::GaloisFieldCalculator;
use crate::packet::{
    Par2CreatorData, Par2FileDescriptionData, Par2MainData, Par2PacketBody, Par2PacketHeader,
    Par2RecoverySetId, Par2RecoverySliceData, Par2SliceChecksumData,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use colored::Colorize;
use log::info;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) fn create(
    slice_size: u64,
    recovery_block_count: u16,
    base_output_file: &Path,
    input_files: &[PathBuf],
    creator: &str,
) -> Result<(), Par2Error> {
    let parent = base_output_file.parent().unwrap_or(Path::new("."));
    let file_plan = plan_recovery_files(&base_output_file, recovery_block_count)?;

    for spec in &file_plan {
        let output_file_path = parent.join(&spec.file_name);
        if output_file_path.exists() {
            return Err(Par2Error::FilePathError(format!(
                "file at path \"{}\" already exists",
                output_file_path.display(),
            )));
        }
    }

    let file_data = compute_files(slice_size, &input_files)?;

    let sorted_file_paths: Vec<PathBuf> = file_data.iter().map(|f| f.file_path.clone()).collect();

    let total_input_slices: usize = file_data
        .iter()
        .map(|d| d.computed_slice_checksums.len())
        .sum();

    let source_file_count = file_data.len();
    let recovery_file_count = file_plan.iter().filter(|s| s.block_count > 0).count();

    info!("Block size: {}", slice_size);
    info!("Source file count: {}", source_file_count);
    info!("Source block count: {}", total_input_slices);
    info!("Recovery block count: {}", recovery_block_count);
    info!("Recovery file count: {}", recovery_file_count);

    let calculator = GaloisFieldCalculator::new();
    let common = build_common(slice_size, creator, file_data)?;

    if recovery_block_count > 0 {
        info!("Computing recovery data...");
    }

    for spec in &file_plan {
        info!("Writing: {}", spec.file_name.bold());

        let output_file_path = parent.join(&spec.file_name);
        let mut output_file = File::create(output_file_path)?;

        if spec.block_count == 0 {
            output_file.write_all(&common.start_bytes)?;
            output_file.write_all(&common.end_bytes)?;
            continue;
        }

        let mut recovery_slices: Vec<Par2RecoverySliceData> = Vec::new();

        for exponent in spec.starting_exponent..(spec.starting_exponent + spec.block_count) {
            let mut recovery_buffer = vec![0u16; slice_size as usize / 2];
            let mut global_slice_index = 0;

            for input_file_path in &sorted_file_paths {
                let mut input_file = File::open(input_file_path)?;
                let mut input_buffer = vec![0u8; slice_size as usize];

                loop {
                    input_buffer.fill(0);

                    match input_file.read(&mut input_buffer) {
                        Ok(0) => break,
                        Ok(_n) => {
                            let mut cursor = Cursor::new(&input_buffer);
                            let slice_constant =
                                find_slice_constant(&calculator, global_slice_index);
                            let slice_coefficient = calculator.power(slice_constant, exponent);

                            for slice_index in 0..slice_size as usize / 2 {
                                let word = cursor.read_u16::<LittleEndian>()?;

                                recovery_buffer[slice_index] ^=
                                    calculator.multiply(slice_coefficient, word);
                            }

                            global_slice_index += 1;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }

            let mut recovery_bytes = Vec::new();

            for item in recovery_buffer {
                recovery_bytes.write_u16::<LittleEndian>(item)?;
            }

            recovery_slices.push(Par2RecoverySliceData {
                exponent: exponent as u32,
                recovery_data: recovery_bytes,
            })
        }

        for slice in recovery_slices {
            let body = Par2PacketBody::RecoverySlice(slice);
            let body_bytes = body.to_bytes()?;
            let header = Par2PacketHeader::from_body(
                &common.recovery_set_id,
                body.packet_type(),
                &body_bytes,
            );
            let header_bytes = header.to_bytes()?;

            output_file.write_all(&header_bytes)?;
            output_file.write_all(&body_bytes)?;
            output_file.write_all(&common.start_bytes)?;
        }

        output_file.write_all(&common.end_bytes)?;
    }

    info!("{}", "Done".green().bold());

    Ok(())
}

fn find_slice_constant(calculator: &GaloisFieldCalculator, slice_number: u16) -> u16 {
    let mut slice_numbers = Vec::new();

    for i in 1..65534 {
        if i % 3 == 0 || i % 5 == 0 || i % 17 == 0 || i % 257 == 0 {
            continue;
        }

        slice_numbers.push(i);
    }

    calculator.power(2, slice_numbers[slice_number as usize])
}

struct CommonFileData {
    recovery_set_id: Par2RecoverySetId,
    start_bytes: Vec<u8>,
    end_bytes: Vec<u8>,
}

fn build_common(
    slice_size: u64,
    creator: &str,
    file_data: Vec<Par2ComputedFileData>,
) -> Result<CommonFileData, Par2Error> {
    let mut common_start_packets = Vec::new();
    let mut common_end_packets = Vec::new();

    let main_data = Par2MainData {
        non_recovery_file_ids: vec![],
        recovery_file_ids: file_data.iter().map(|c| c.file_id).collect(),
        slice_size,
    };
    let recovery_set_id = main_data.recovery_set_id();
    let main_packet = Par2PacketBody::Main(main_data);

    common_start_packets.push(main_packet);

    let mut file_desc_packets = Vec::with_capacity(file_data.len());
    let mut file_slice_checksum_packets = Vec::with_capacity(file_data.len());

    for file_datum in file_data {
        file_desc_packets.push(Par2PacketBody::FileDesc(Par2FileDescriptionData {
            file_first_16kb_md5: file_datum.first_16kb_md5,
            file_length: file_datum.file_length,
            file_md5: file_datum.file_md5,
            file_name: file_datum.file_name,
        }));

        file_slice_checksum_packets.push(Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
            file_id: file_datum.file_id,
            entries: file_datum.computed_slice_checksums,
        }));
    }

    common_start_packets.extend(file_desc_packets);
    common_start_packets.extend(file_slice_checksum_packets);

    common_end_packets.push(Par2PacketBody::Creator(Par2CreatorData {
        name: creator.to_string(),
    }));

    let mut start_bytes = Cursor::new(Vec::new());
    let mut end_bytes = Cursor::new(Vec::new());

    for body in common_start_packets {
        let body_bytes = body.to_bytes()?;
        let header = Par2PacketHeader::from_body(&recovery_set_id, body.packet_type(), &body_bytes);
        let header_bytes = header.to_bytes()?;

        start_bytes.write_all(&header_bytes)?;
        start_bytes.write_all(&body_bytes)?;
    }

    for body in common_end_packets {
        let body_bytes = body.to_bytes()?;
        let header = Par2PacketHeader::from_body(&recovery_set_id, body.packet_type(), &body_bytes);
        let header_bytes = header.to_bytes()?;

        end_bytes.write_all(&header_bytes)?;
        end_bytes.write_all(&body_bytes)?;
    }

    Ok(CommonFileData {
        recovery_set_id,
        start_bytes: start_bytes.into_inner(),
        end_bytes: end_bytes.into_inner(),
    })
}

fn compute_files(
    slice_size: u64,
    files: &[PathBuf],
) -> Result<Vec<Par2ComputedFileData>, Par2Error> {
    let mut seen = HashSet::new();
    let mut file_data = Vec::new();

    for file_path in files {
        if !seen.insert(file_path) {
            return Err(Par2Error::DuplicateInputFile);
        }

        let checksums = compute_file_data(file_path, slice_size)?;

        file_data.push(checksums);
    }

    file_data.sort_by_key(|c| c.file_id);

    Ok(file_data)
}
