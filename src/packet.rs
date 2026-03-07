use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt};
use md5::{Digest, Md5};
use std::io::{Cursor, Read};

pub type Par2RecoverySetId = [u8; 16];

pub type Par2FileId = [u8; 16];

pub type Par2Md5Hash = [u8; 16];

pub struct Par2Packet {
    pub header: Par2PacketHeader,
    pub body: Par2PacketBody,
}

pub struct Par2PacketHeader {
    packet_length: u64,
    pub expected_md5: Par2Md5Hash,
    pub computed_md5: Option<Par2Md5Hash>,
    pub recovery_set_id: Par2RecoverySetId,
    packet_type: [u8; 16],
}

#[derive(Debug)]
pub enum Par2PacketBody {
    Main(Par2MainData),
    FileDesc(Par2FileDescriptionData),
    SliceChecksum(Par2SliceChecksumData),
    RecoverySlice(Par2RecoverySliceData),
    Creator(Par2CreatorData),
    Unknown(Vec<u8>),
}

#[derive(Debug)]
pub struct Par2MainData {
    pub slice_size: u64,
    pub file_ids: Vec<Par2FileId>,
}

#[derive(Debug)]
pub struct Par2FileDescriptionData {
    file_id: Par2FileId,
    file_md5: Par2Md5Hash,
    file_first_16kb_md5: Par2Md5Hash,
    file_length: u64,
    file_name: Vec<u8>, // ASCII bytes (not null-terminated, zero-padded to 4-byte alignment)
}

#[derive(Debug)]
pub struct Par2SliceChecksumData {
    file_id: Par2FileId,
    entries: Vec<Par2SliceChecksumEntry>,
}

#[derive(Debug)]
pub struct Par2SliceChecksumEntry {
    md5: Par2Md5Hash,
    crc32: u32,
}

#[derive(Debug)]
pub struct Par2RecoverySliceData {
    exponent: u32,
    recovery_data: Vec<u8>,
}

#[derive(Debug)]
pub struct Par2CreatorData {
    name: Vec<u8>,
}

pub const PAR2_PACKET_MAGIC_HEADER: &[u8] = b"PAR2\0PKT";
pub const PAR2_PACKET_MAGIC_MAIN: &[u8] = b"PAR 2.0\0Main\0\0\0\0";
pub const PAR2_PACKET_MAGIC_FILE_DESC: &[u8] = b"PAR 2.0\0FileDesc";
pub const PAR2_PACKET_MAGIC_SLICE_CHECKSUM: &[u8] = b"PAR 2.0\0IFSC\0\0\0\0";
pub const PAR2_PACKET_MAGIC_RECOVERY_SLICE: &[u8] = b"PAR 2.0\0RecvSlic";
pub const PAR2_PACKET_MAGIC_CREATOR: &[u8] = b"PAR 2.0\0Creator\0";

const PAR2_HEADER_SIZE: usize = 64;
const PAR2_HASH_START_OFFSET: usize = 32;

pub fn parse_file(file_path: &std::path::Path) -> Result<Vec<Par2Packet>, Par2Error> {
    let file_data = std::fs::read(file_path)?;
    let file_size = file_data.len();
    let mut offset = 0;
    let mut packets = Vec::new();

    while offset < file_size {
        match find_next_header_offset(&file_data[offset..]) {
            Some(relative_offset) => {
                let header_offset = offset + relative_offset;

                let mut header = parse_header(&file_data[header_offset..]).map_err(|e| {
                    Par2Error::ParseError(format!(
                        "Failed to parse header at offset [{}]: {}",
                        header_offset, e
                    ))
                })?;

                // The packet length must be large enough to contain the entire header.
                if header.packet_length < PAR2_HEADER_SIZE as u64 {
                    return Err(Par2Error::ParseError(format!(
                        "Header packet length [{}] is less than minimum required [{}]",
                        header.packet_length, PAR2_HEADER_SIZE,
                    )));
                }

                let header_hash_start_position = header_offset + PAR2_HASH_START_OFFSET;
                let header_hash_end_position =
                    header_offset.saturating_add(header.packet_length as usize);

                if header_hash_end_position > file_size {
                    return Err(Par2Error::ParseError(format!(
                        "Header hash end position [{}] exceeds file size [{}]",
                        header_hash_end_position, file_size
                    )));
                }

                let mut hasher = Md5::new();
                hasher.update(&file_data[header_hash_start_position..header_hash_end_position]);
                header.computed_md5 = Some(hasher.finalize().into());

                let header_packet_length = header.packet_length as usize;

                if header_packet_length > file_size - offset {
                    return Err(Par2Error::ParseError(format!(
                        "Failed to parse header at offset [{}], length [{}] exceeds file size [{}]",
                        header_offset, header_packet_length, file_size
                    )));
                }

                println!(
                    "Parsed header at [{}], length {}",
                    header_offset, header_packet_length
                );

                let body_offset = header_offset + PAR2_HEADER_SIZE;
                let body_bytes = &file_data[body_offset..header_offset + header_packet_length];

                let body = parse_body(&header.packet_type, body_bytes).map_err(|e| {
                    Par2Error::ParseError(format!(
                        "Failed to parse body at offset [{}]: {}",
                        header_offset, e
                    ))
                })?;

                println!(
                    "Parsed body at [{}], length {}",
                    body_offset,
                    body_bytes.len()
                );

                packets.push(Par2Packet { header, body });

                // Move to the next packet
                offset = header_offset + header_packet_length;
            }
            None => break,
        }
    }

    Ok(packets)
}

fn find_next_header_offset(data: &[u8]) -> Option<usize> {
    let mut offset = 0;
    let total_size = data.len();
    let magic_size = PAR2_PACKET_MAGIC_HEADER.len();

    while offset + magic_size <= total_size {
        let magic_bytes = &data[offset..offset + magic_size];

        if magic_bytes == PAR2_PACKET_MAGIC_HEADER {
            return Some(offset);
        }

        offset += 1;
    }

    None
}

fn parse_header(data: &[u8]) -> Result<Par2PacketHeader, Par2Error> {
    let mut cursor = Cursor::new(data);

    let mut magic_bytes = [0; PAR2_PACKET_MAGIC_HEADER.len()];
    cursor.read_exact(&mut magic_bytes)?;

    if magic_bytes != PAR2_PACKET_MAGIC_HEADER {
        return Err(Par2Error::ParseError(format!(
            "Invalid magic bytes: {:?}",
            magic_bytes
        )));
    }

    let packet_length = cursor
        .read_u64::<LittleEndian>()
        .map_err(|e| Par2Error::ParseError(format!("Failed to read packet length: {}", e)))?;

    let mut expected_md5: [u8; 16] = [0; 16];
    cursor
        .read_exact(&mut expected_md5)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read MD5: {}", e)))?;

    let mut recovery_set_id: [u8; 16] = [0; 16];
    cursor
        .read_exact(&mut recovery_set_id)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read recovery set ID: {}", e)))?;

    let mut packet_type: [u8; 16] = [0; 16];
    cursor
        .read_exact(&mut packet_type)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read packet type: {}", e)))?;

    Ok(Par2PacketHeader {
        packet_length,
        expected_md5,
        computed_md5: None,
        recovery_set_id,
        packet_type,
    })
}

fn parse_body(packet_type: &[u8], data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    match packet_type {
        PAR2_PACKET_MAGIC_MAIN => parse_body_main(data),
        PAR2_PACKET_MAGIC_FILE_DESC => parse_file_description(data),
        PAR2_PACKET_MAGIC_SLICE_CHECKSUM => parse_slice_checksum(data),
        PAR2_PACKET_MAGIC_RECOVERY_SLICE => parse_recovery_slice(data),
        PAR2_PACKET_MAGIC_CREATOR => parse_creator(data),
        _ => Ok(Par2PacketBody::Unknown(data.to_vec())),
    }
}

fn parse_body_main(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut cursor = Cursor::new(data);

    let slice_size = cursor
        .read_u64::<LittleEndian>()
        .map_err(|e| Par2Error::ParseError(format!("Failed to read slice size: {}", e)))?;

    let file_count = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| Par2Error::ParseError(format!("Failed to read file count: {}", e)))?;

    let required_bytes = (file_count as u64).saturating_mul(16);
    let remaining_bytes = cursor.get_ref().len() as u64 - cursor.position();

    if required_bytes > remaining_bytes {
        return Err(Par2Error::ParseError(format!(
            "File count {} exceeds available data",
            file_count
        )));
    }

    let mut file_ids = Vec::with_capacity(file_count as usize);

    for _ in 0..file_count {
        let mut file_id = [0; 16];

        cursor
            .read_exact(&mut file_id)
            .map_err(|e| Par2Error::ParseError(format!("Failed to read file ID: {}", e)))?;

        file_ids.push(file_id);
    }

    Ok(Par2PacketBody::Main(Par2MainData {
        slice_size,
        file_ids,
    }))
}

fn parse_file_description(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut cursor = Cursor::new(data);

    let mut file_id = [0; 16];
    cursor
        .read_exact(&mut file_id)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file ID: {}", e)))?;

    let mut file_md5 = [0; 16];
    cursor
        .read_exact(&mut file_md5)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file MD5: {}", e)))?;

    let mut file_first_16kb_md5 = [0; 16];
    cursor.read_exact(&mut file_first_16kb_md5).map_err(|e| {
        Par2Error::ParseError(format!(
            "Failed to read FileDesc file first 16KB MD5: {}",
            e
        ))
    })?;

    let file_length = cursor.read_u64::<LittleEndian>().map_err(|e| {
        Par2Error::ParseError(format!("Failed to read FileDesc file length: {}", e))
    })?;

    let mut file_name = vec![0; data.len() - cursor.position() as usize];
    cursor
        .read_exact(&mut file_name)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file name: {}", e)))?;

    let trailing_null_bytes = file_name
        .iter()
        .rposition(|&b| b == 0)
        .unwrap_or(file_name.len());
    file_name.truncate(trailing_null_bytes);

    Ok(Par2PacketBody::FileDesc(Par2FileDescriptionData {
        file_id,
        file_md5,
        file_first_16kb_md5,
        file_length,
        file_name,
    }))
}

fn parse_slice_checksum(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut cursor = Cursor::new(data);

    let mut file_id = [0; 16];
    cursor
        .read_exact(&mut file_id)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read IFSC file ID: {}", e)))?;

    let entry_bytes = cursor.get_ref().len() - cursor.position() as usize;
    if entry_bytes % 20 != 0 {
        return Err(Par2Error::ParseError("Invalid IFSC entry size".to_string()));
    }

    let entry_count = entry_bytes / 20;
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        let mut md5 = [0; 16];
        cursor
            .read_exact(&mut md5)
            .map_err(|e| Par2Error::ParseError(format!("Failed to read IFSC entry MD5: {}", e)))?;

        let crc32 = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Par2Error::ParseError(format!("Failed to read IFSC entry CRC32: {}", e))
        })?;

        entries.push(Par2SliceChecksumEntry { md5, crc32 });
    }

    Ok(Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
        file_id,
        entries,
    }))
}

fn parse_recovery_slice(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut cursor = Cursor::new(data);

    let exponent = cursor.read_u32::<LittleEndian>().map_err(|e| {
        Par2Error::ParseError(format!("Failed to read recovery slice exponent: {}", e))
    })?;

    let slice_size = cursor.get_ref().len() - cursor.position() as usize;
    let mut recovery_data = Vec::with_capacity(slice_size);

    cursor
        .read_to_end(&mut recovery_data)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read recovery slice data: {}", e)))?;

    Ok(Par2PacketBody::RecoverySlice(Par2RecoverySliceData {
        exponent,
        recovery_data,
    }))
}

fn parse_creator(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut file_name = data.to_vec();

    let trailing_null_bytes = file_name
        .iter()
        .rposition(|&b| b == 0)
        .unwrap_or(file_name.len());
    file_name.truncate(trailing_null_bytes);

    Ok(Par2PacketBody::Creator(Par2CreatorData { name: file_name }))
}
