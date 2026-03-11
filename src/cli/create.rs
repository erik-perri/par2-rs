use crate::error::Par2Error;
use crate::file::compute_file_data;
use crate::packet::{
    Par2CreatorData, Par2FileDescriptionData, Par2MainData, Par2PacketBody, Par2PacketHeader,
    Par2SliceChecksumData,
};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

pub(crate) fn create(
    slice_size: u64,
    _recovery_block_count: u16,
    output: &Path,
    files: &[PathBuf],
    creator: &str,
) -> Result<(), Par2Error> {
    let mut seen = HashSet::new();
    let mut file_data = Vec::new();
    let mut total_input_slices = 0;

    for file_path in files {
        if !seen.insert(file_path) {
            return Err(Par2Error::DuplicateInputFile);
        }

        let checksums = compute_file_data(file_path, slice_size)?;

        total_input_slices += checksums.computed_slice_checksums.len();

        file_data.push(checksums);
    }

    file_data.sort_by_key(|c| c.file_id);

    println!("Total input slices: {}", total_input_slices);

    let mut packets = Vec::new();

    let main_data = Par2MainData {
        non_recovery_file_ids: vec![],
        recovery_file_ids: file_data.iter().map(|c| c.file_id).collect(),
        slice_size,
    };
    let recovery_set_id = main_data.recovery_set_id();
    let main_packet = Par2PacketBody::Main(main_data);

    println!("Recovery set ID: {:?}", recovery_set_id);

    packets.push(main_packet);

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

    packets.extend(file_desc_packets);
    packets.extend(file_slice_checksum_packets);

    packets.push(Par2PacketBody::Creator(Par2CreatorData {
        name: creator.to_string(),
    }));

    let mut file_buffer = Cursor::new(Vec::new());

    for body in packets {
        let body_bytes = body.to_bytes()?;

        let header = Par2PacketHeader::from_body(&recovery_set_id, body.packet_type(), &body_bytes);

        let header_bytes = header.to_bytes()?;

        file_buffer.write_all(&header_bytes)?;
        file_buffer.write_all(&body_bytes)?;
    }

    println!("Writing {}", output.display());

    let mut file = File::create(output)?;
    file.write_all(&file_buffer.into_inner())?;

    Ok(())
}
