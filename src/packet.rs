use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt};
use md5::{Digest, Md5};
use std::fmt::Display;
use std::io::{Cursor, Read};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Par2FileId(pub(crate) [u8; 16]);

impl AsMut<[u8]> for Par2FileId {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Par2FileId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Par2Md5Hash> for Par2FileId {
    fn from(hash: Par2Md5Hash) -> Self {
        Self(hash.0)
    }
}

impl Display for Par2FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Par2Md5Hash(pub(crate) [u8; 16]);

impl AsMut<[u8]> for Par2Md5Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Par2Md5Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Par2RecoverySetId(pub(crate) [u8; 16]);

impl AsMut<[u8]> for Par2RecoverySetId {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Par2RecoverySetId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Par2Md5Hash> for Par2RecoverySetId {
    fn from(hash: Par2Md5Hash) -> Self {
        Self(hash.0)
    }
}

pub type Par2PacketType = [u8; 16];

pub struct Par2Packet {
    pub(crate) header: Par2PacketHeader,
    pub(crate) body: Par2PacketBody,
}

pub struct Par2PacketHeader {
    pub(crate) packet_length: u64,
    pub(crate) expected_md5: Par2Md5Hash,
    pub(crate) computed_md5: Option<Par2Md5Hash>,
    pub(crate) recovery_set_id: Par2RecoverySetId,
    pub(crate) packet_type: Par2PacketType,
}

#[derive(Debug)]
pub enum Par2PacketBody {
    Main(Par2MainData),
    FileDesc(Par2FileDescriptionData),
    SliceChecksum(Par2SliceChecksumData),
    RecoverySlice(Par2RecoverySliceData),
    Creator(Par2CreatorData),
    Unknown(Par2PacketType),
}

#[derive(Debug)]
pub struct Par2MainData {
    pub(crate) computed_recovery_set_id: Par2RecoverySetId,
    pub(crate) non_recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_file_ids: Vec<Par2FileId>,
    pub(crate) slice_size: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Par2FileDescriptionData {
    pub(crate) file_id: Par2FileId,
    pub(crate) file_md5: Par2Md5Hash,
    pub(crate) file_first_16kb_md5: Par2Md5Hash,
    pub(crate) file_length: u64,
    pub(crate) file_name: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Par2SliceChecksumData {
    pub(crate) file_id: Par2FileId,
    pub(crate) entries: Vec<Par2SliceChecksumEntry>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Par2SliceChecksumEntry {
    pub(crate) md5: Par2Md5Hash,
    pub(crate) crc32: u32,
}

#[derive(Debug)]
pub struct Par2RecoverySliceData {
    pub(crate) exponent: u32,
    pub(crate) recovery_data: Vec<u8>,
}

#[derive(Debug)]
pub struct Par2CreatorData {
    pub(crate) name: Vec<u8>,
}

pub const PAR2_PACKET_MAGIC_HEADER: &[u8] = b"PAR2\0PKT";
pub const PAR2_PACKET_MAGIC_MAIN: &Par2PacketType = b"PAR 2.0\0Main\0\0\0\0";
pub const PAR2_PACKET_MAGIC_FILE_DESC: &Par2PacketType = b"PAR 2.0\0FileDesc";
pub const PAR2_PACKET_MAGIC_SLICE_CHECKSUM: &Par2PacketType = b"PAR 2.0\0IFSC\0\0\0\0";
pub const PAR2_PACKET_MAGIC_RECOVERY_SLICE: &Par2PacketType = b"PAR 2.0\0RecvSlic";
pub const PAR2_PACKET_MAGIC_CREATOR: &Par2PacketType = b"PAR 2.0\0Creator\0";

const PAR2_HEADER_SIZE: usize = 64;
const PAR2_HASH_START_OFFSET: usize = 32;

pub fn parse_file(file_path: &std::path::Path) -> Result<Vec<Par2Packet>, Par2Error> {
    let file_data = std::fs::read(file_path)?;
    let file_size = file_data.len();
    let mut offset = 0;
    let mut packets = Vec::new();

    while offset < file_size {
        let Some(relative_offset) = find_next_header_offset(&file_data[offset..]) else {
            break;
        };

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
        let header_hash_end_position = header_offset.saturating_add(header.packet_length as usize);

        if header_hash_end_position > file_size {
            return Err(Par2Error::ParseError(format!(
                "Header hash end position [{}] exceeds file size [{}]",
                header_hash_end_position, file_size
            )));
        }

        let computed_header_md5 = Par2Md5Hash(
            Md5::digest(&file_data[header_hash_start_position..header_hash_end_position]).into(),
        );

        header.computed_md5 = Some(computed_header_md5);

        let header_packet_length = header.packet_length as usize;

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

    Ok(packets)
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

    let mut expected_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
    cursor
        .read_exact(expected_md5.as_mut())
        .map_err(|e| Par2Error::ParseError(format!("Failed to read MD5: {}", e)))?;

    let mut recovery_set_id: Par2RecoverySetId = Par2RecoverySetId([0; 16]);
    cursor
        .read_exact(recovery_set_id.as_mut())
        .map_err(|e| Par2Error::ParseError(format!("Failed to read recovery set ID: {}", e)))?;

    let mut packet_type: Par2PacketType = [0; 16];
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

fn parse_body(packet_type: &Par2PacketType, data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    match packet_type {
        PAR2_PACKET_MAGIC_MAIN => parse_body_main(data),
        PAR2_PACKET_MAGIC_FILE_DESC => parse_file_description(data),
        PAR2_PACKET_MAGIC_SLICE_CHECKSUM => parse_slice_checksum(data),
        PAR2_PACKET_MAGIC_RECOVERY_SLICE => parse_recovery_slice(data),
        PAR2_PACKET_MAGIC_CREATOR => parse_creator(data),
        _ => Ok(Par2PacketBody::Unknown(*packet_type)),
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

    let mut recovery_file_ids = Vec::with_capacity(file_count as usize);

    for _ in 0..file_count {
        let mut file_id: Par2FileId = Par2FileId([0; 16]);

        cursor
            .read_exact(file_id.as_mut())
            .map_err(|e| Par2Error::ParseError(format!("Failed to read file ID: {}", e)))?;

        recovery_file_ids.push(file_id);
    }

    let remaining_bytes = cursor.get_ref().len() as u64 - cursor.position();
    if !remaining_bytes.is_multiple_of(16) {
        return Err(Par2Error::ParseError(format!(
            "Found {} bytes remaining after reading recovery file IDs, expected 16 bytes per verification file ID",
            remaining_bytes
        )));
    }

    let non_recovery_file_count = remaining_bytes / 16;
    let mut non_recovery_file_ids = Vec::with_capacity(non_recovery_file_count as usize);

    for _ in 0..non_recovery_file_count {
        let mut file_id: Par2FileId = Par2FileId([0; 16]);
        cursor.read_exact(file_id.as_mut()).map_err(|e| {
            Par2Error::ParseError(format!("Failed to read verification file ID: {}", e))
        })?;

        non_recovery_file_ids.push(file_id);
    }

    let body_md5 = Par2Md5Hash(Md5::digest(data).into());
    let computed_recovery_set_id = Par2RecoverySetId::from(body_md5);

    Ok(Par2PacketBody::Main(Par2MainData {
        computed_recovery_set_id,
        non_recovery_file_ids,
        recovery_file_ids,
        slice_size,
    }))
}

fn parse_file_description(data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    let mut cursor = Cursor::new(data);

    let mut file_id: Par2FileId = Par2FileId([0; 16]);
    cursor
        .read_exact(file_id.as_mut())
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file ID: {}", e)))?;

    let mut file_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
    cursor
        .read_exact(file_md5.as_mut())
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file MD5: {}", e)))?;

    let mut file_first_16kb_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
    cursor
        .read_exact(file_first_16kb_md5.as_mut())
        .map_err(|e| {
            Par2Error::ParseError(format!(
                "Failed to read FileDesc file first 16KB MD5: {}",
                e
            ))
        })?;

    let file_length = cursor.read_u64::<LittleEndian>().map_err(|e| {
        Par2Error::ParseError(format!("Failed to read FileDesc file length: {}", e))
    })?;

    let mut parsed_name = vec![0; data.len() - cursor.position() as usize];
    cursor
        .read_exact(&mut parsed_name)
        .map_err(|e| Par2Error::ParseError(format!("Failed to read FileDesc file name: {}", e)))?;

    let file_name_bytes = trim_trailing_null_bytes(&parsed_name);
    let file_name = match String::from_utf8(file_name_bytes) {
        Ok(name) => name,
        Err(_) => {
            return Err(Par2Error::ParseError(
                "Failed to decode FileDesc file name as UTF-8".to_string(),
            ));
        }
    };

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

    let mut file_id: Par2FileId = Par2FileId([0; 16]);
    cursor
        .read_exact(file_id.as_mut())
        .map_err(|e| Par2Error::ParseError(format!("Failed to read IFSC file ID: {}", e)))?;

    let entry_bytes = cursor.get_ref().len() - cursor.position() as usize;
    if !entry_bytes.is_multiple_of(20) {
        return Err(Par2Error::ParseError("Invalid IFSC entry size".to_string()));
    }

    let entry_count = entry_bytes / 20;
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        let mut md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
        cursor
            .read_exact(md5.as_mut())
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
    let name = trim_trailing_null_bytes(data);

    Ok(Par2PacketBody::Creator(Par2CreatorData { name }))
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

fn trim_trailing_null_bytes(data: &[u8]) -> Vec<u8> {
    let last_non_null_byte = data.iter().rposition(|&b| b != 0);

    if let Some(last_non_null_byte) = last_non_null_byte {
        return data[..last_non_null_byte + 1].to_vec();
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod parse_header {
        use super::*;
        use byteorder::WriteBytesExt;
        use std::io::Write;

        fn build_header_bytes(
            packet_length: u64,
            expected_md5: Par2Md5Hash,
            recovery_set_id: Par2RecoverySetId,
            packet_type: Par2PacketType,
            magic_bytes: Option<&[u8]>,
        ) -> [u8; 64] {
            let mut cursor = Cursor::new(Vec::new());

            cursor
                .write_all(magic_bytes.unwrap_or(PAR2_PACKET_MAGIC_HEADER))
                .unwrap();
            cursor.write_u64::<LittleEndian>(packet_length).unwrap();
            cursor.write_all(expected_md5.as_ref()).unwrap();
            cursor.write_all(recovery_set_id.as_ref()).unwrap();
            cursor.write_all(packet_type.as_ref()).unwrap();

            cursor.into_inner().try_into().unwrap()
        }

        #[test]
        fn parses_header() {
            let header_bytes = build_header_bytes(
                1234,
                Par2Md5Hash([0xAA; 16]),
                Par2RecoverySetId([0xBB; 16]),
                [0xCC; 16],
                None,
            );

            let parsed_header = parse_header(&header_bytes).unwrap();

            assert_eq!(parsed_header.packet_length, 1234);
            assert_eq!(parsed_header.expected_md5, Par2Md5Hash([0xAA; 16]));
            assert_eq!(parsed_header.recovery_set_id, Par2RecoverySetId([0xBB; 16]));
            assert_eq!(parsed_header.packet_type, [0xCC; 16]);
        }

        #[test]
        fn truncated_below_magic_bytes() {
            let header_bytes = build_header_bytes(
                1234,
                Par2Md5Hash([0xDD; 16]),
                Par2RecoverySetId([0xEE; 16]),
                [0xFF; 16],
                None,
            );

            let truncated = &header_bytes[0..4];

            assert!(parse_header(truncated).is_err());
        }

        #[test]
        fn truncated_after_magic_bytes() {
            let header_bytes = build_header_bytes(
                1234,
                Par2Md5Hash([0xFF; 16]),
                Par2RecoverySetId([0xEE; 16]),
                [0xDD; 16],
                None,
            );

            let truncated = &header_bytes[0..32];

            assert!(parse_header(truncated).is_err());
        }

        #[test]
        fn invalid_magic_bytes() {
            let header_bytes = build_header_bytes(
                1234,
                Par2Md5Hash([0xAA; 16]),
                Par2RecoverySetId([0xBB; 16]),
                [0xCC; 16],
                Some(b"INVALID\0"),
            );

            assert!(parse_header(&header_bytes).is_err());
        }
    }

    mod parse_body {
        use super::*;

        #[test]
        fn main_type_routing() {
            let packet_type = PAR2_PACKET_MAGIC_MAIN;
            let body_bytes: Vec<u8> = vec![0x00; 12];

            let parsed_body = parse_body(packet_type, &body_bytes).unwrap();
            let Par2PacketBody::Main(_) = parsed_body else {
                panic!("Expected Main variant");
            };
        }

        #[test]
        fn file_desc_type_routing() {
            let packet_type = PAR2_PACKET_MAGIC_FILE_DESC;
            let body_bytes: Vec<u8> = vec![0x00; 64];

            let parsed_body = parse_body(packet_type, &body_bytes).unwrap();
            let Par2PacketBody::FileDesc(_) = parsed_body else {
                panic!("Expected FileDesc variant");
            };
        }

        #[test]
        fn slice_checksum_type_routing() {
            let packet_type = PAR2_PACKET_MAGIC_SLICE_CHECKSUM;
            let body_bytes: Vec<u8> = vec![0x00; 56];

            let parsed_body = parse_body(packet_type, &body_bytes).unwrap();
            let Par2PacketBody::SliceChecksum(_) = parsed_body else {
                panic!("Expected SliceChecksum variant");
            };
        }

        #[test]
        fn recovery_slice_type_routing() {
            let packet_type = PAR2_PACKET_MAGIC_RECOVERY_SLICE;
            let body_bytes: Vec<u8> = vec![0x00; 12];

            let parsed_body = parse_body(packet_type, &body_bytes).unwrap();
            let Par2PacketBody::RecoverySlice(_) = parsed_body else {
                panic!("Expected RecoverySlice variant");
            };
        }

        #[test]
        fn creator_type_routing() {
            let packet_type = PAR2_PACKET_MAGIC_CREATOR;
            let body_bytes: Vec<u8> = vec![0x00; 16];

            let parsed_body = parse_body(packet_type, &body_bytes).unwrap();
            let Par2PacketBody::Creator(_) = parsed_body else {
                panic!("Expected Creator variant");
            };
        }

        #[test]
        fn unknown_type_routing() {
            let packet_type = [0xCC; 16];
            let body_bytes: Vec<u8> = vec![0x00; 16];

            let parsed_body = parse_body(&packet_type, &body_bytes).unwrap();
            let Par2PacketBody::Unknown(unknown_type) = parsed_body else {
                panic!("Expected Unknown variant");
            };

            assert_eq!(unknown_type, packet_type);
        }
    }

    mod parse_body_main {
        use super::*;
        use byteorder::WriteBytesExt;
        use std::io::Write;

        fn build_body_main_bytes(
            slice_size: u64,
            recovery_file_ids: &[Par2FileId],
            non_recovery_file_ids: &[Par2FileId],
            file_count: Option<u32>,
        ) -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());

            cursor.write_u64::<LittleEndian>(slice_size).unwrap();

            let file_count = file_count.unwrap_or(recovery_file_ids.len() as u32);
            cursor.write_u32::<LittleEndian>(file_count).unwrap();

            for file_id in recovery_file_ids {
                cursor.write_all(file_id.as_ref()).unwrap();
            }
            for file_id in non_recovery_file_ids {
                cursor.write_all(file_id.as_ref()).unwrap();
            }

            cursor.into_inner()
        }

        #[test]
        fn normal_body() {
            let body_bytes = build_body_main_bytes(
                1234,
                &[Par2FileId([0xAA; 16]), Par2FileId([0xBB; 16])],
                &[],
                None,
            );

            let parsed_body = parse_body_main(&body_bytes).unwrap();
            let Par2PacketBody::Main(main_data) = parsed_body else {
                panic!("Expected Main variant");
            };

            assert_eq!(main_data.slice_size, 1234);
            assert_eq!(main_data.recovery_file_ids.len(), 2);
            assert_eq!(main_data.recovery_file_ids[0], Par2FileId([0xAA; 16]));
            assert_eq!(main_data.recovery_file_ids[1], Par2FileId([0xBB; 16]));

            assert_eq!(main_data.non_recovery_file_ids.len(), 0);
        }

        #[test]
        fn non_recovery_files() {
            let body_bytes = build_body_main_bytes(1234, &[], &[Par2FileId([0xCC; 16])], None);

            let parsed_body = parse_body_main(&body_bytes).unwrap();
            let Par2PacketBody::Main(main_data) = parsed_body else {
                panic!("Expected Main variant");
            };

            assert_eq!(main_data.slice_size, 1234);

            assert_eq!(main_data.recovery_file_ids.len(), 0);

            assert_eq!(main_data.non_recovery_file_ids.len(), 1);
            assert_eq!(main_data.non_recovery_file_ids[0], Par2FileId([0xCC; 16]),)
        }

        #[test]
        fn invalid_file_count() {
            let body_bytes = build_body_main_bytes(1234, &[], &[], Some(10));

            assert!(parse_body_main(&body_bytes).is_err());
        }

        #[test]
        fn unexpected_size() {
            let body_bytes = build_body_main_bytes(
                1234,
                &[Par2FileId([0xCC; 16])],
                &[Par2FileId([0xBB; 16])],
                None,
            );
            let truncated = &body_bytes[0..body_bytes.len() - 4];

            assert!(parse_body_main(truncated).is_err());
        }
    }

    mod parse_file_description {
        use super::*;
        use byteorder::WriteBytesExt;
        use std::io::Write;

        fn build_file_description_bytes(
            file_id: Par2FileId,
            file_md5: Par2Md5Hash,
            file_first_16kb_md5: Par2Md5Hash,
            file_length: u64,
            file_name: &[u8],
        ) -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());

            cursor.write_all(file_id.as_ref()).unwrap();
            cursor.write_all(file_md5.as_ref()).unwrap();
            cursor.write_all(file_first_16kb_md5.as_ref()).unwrap();
            cursor.write_u64::<LittleEndian>(file_length).unwrap();

            let padding_bytes = (4 - (file_name.len() % 4)) % 4;
            let file_name_padding = vec![0; padding_bytes];

            cursor.write_all(file_name).unwrap();
            cursor.write_all(&file_name_padding).unwrap();

            cursor.into_inner()
        }

        #[test]
        fn normal_file_description() {
            let file_description_bytes = build_file_description_bytes(
                Par2FileId([0xAA; 16]),
                Par2Md5Hash([0xBB; 16]),
                Par2Md5Hash([0xCC; 16]),
                1234,
                b"a.txt", // 3 bytes of padding
            );

            let parsed_body = parse_file_description(&file_description_bytes).unwrap();
            let Par2PacketBody::FileDesc(file_desc) = parsed_body else {
                panic!("Expected FileDesc variant");
            };

            assert_eq!(file_desc.file_id, Par2FileId([0xAA; 16]));
            assert_eq!(file_desc.file_md5, Par2Md5Hash([0xBB; 16]));
            assert_eq!(file_desc.file_first_16kb_md5, Par2Md5Hash([0xCC; 16]));
            assert_eq!(file_desc.file_length, 1234);
            assert_eq!(file_desc.file_name, "a.txt");
        }

        #[test]
        fn no_name_padding() {
            let file_description_bytes = build_file_description_bytes(
                Par2FileId([0xAA; 16]),
                Par2Md5Hash([0xBB; 16]),
                Par2Md5Hash([0xCC; 16]),
                1234,
                b"test.txt", // 0 bytes of padding
            );

            let parsed_body = parse_file_description(&file_description_bytes).unwrap();
            let Par2PacketBody::FileDesc(file_desc) = parsed_body else {
                panic!("Expected FileDesc variant");
            };

            assert_eq!(file_desc.file_name, "test.txt");
        }

        #[test]
        fn minimal_name_padding() {
            let file_description_bytes = build_file_description_bytes(
                Par2FileId([0xAA; 16]),
                Par2Md5Hash([0xBB; 16]),
                Par2Md5Hash([0xCC; 16]),
                1234,
                b"testtxt", // 1 byte of padding
            );

            let parsed_body = parse_file_description(&file_description_bytes).unwrap();
            let Par2PacketBody::FileDesc(file_desc) = parsed_body else {
                panic!("Expected FileDesc variant");
            };

            assert_eq!(file_desc.file_name, "testtxt");
        }

        #[test]
        fn too_short() {
            let file_description_bytes = [0xAA; 32];

            let parsed_body = parse_file_description(&file_description_bytes);

            assert!(parsed_body.is_err());
            assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
        }

        #[test]
        fn invalid_name() {
            let file_description_bytes = build_file_description_bytes(
                Par2FileId([0xAA; 16]),
                Par2Md5Hash([0xBB; 16]),
                Par2Md5Hash([0xCC; 16]),
                1234,
                &[0xAA; 32],
            );

            let parsed_body = parse_file_description(&file_description_bytes);

            assert!(parsed_body.is_err());
            assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
        }
    }

    mod parse_slice_checksum {
        use super::*;
        use byteorder::WriteBytesExt;
        use std::io::Write;

        fn build_slice_checksum_bytes(
            file_id: Par2FileId,
            entries: &[(Par2Md5Hash, u32)],
        ) -> Vec<u8> {
            let mut cursor = Cursor::new(Vec::new());
            cursor.write_all(file_id.as_ref()).unwrap();
            for (md5, crc) in entries {
                cursor.write_all(md5.as_ref()).unwrap();
                cursor.write_u32::<LittleEndian>(*crc).unwrap();
            }
            cursor.into_inner()
        }

        #[test]
        fn single_entry() {
            let data = build_slice_checksum_bytes(
                Par2FileId([0xAA; 16]),
                &[(Par2Md5Hash([0xBB; 16]), 0xDEADBEEF)],
            );

            let parsed = parse_slice_checksum(&data).unwrap();
            let Par2PacketBody::SliceChecksum(sc) = parsed else {
                panic!("Expected SliceChecksum variant");
            };

            assert_eq!(sc.file_id, Par2FileId([0xAA; 16]));
            assert_eq!(sc.entries.len(), 1);
            assert_eq!(sc.entries[0].md5, Par2Md5Hash([0xBB; 16]));
            assert_eq!(sc.entries[0].crc32, 0xDEADBEEF);
        }

        #[test]
        fn multiple_entries() {
            let data = build_slice_checksum_bytes(
                Par2FileId([0x11; 16]),
                &[
                    (Par2Md5Hash([0x22; 16]), 0x00000001),
                    (Par2Md5Hash([0x33; 16]), 0x00000002),
                    (Par2Md5Hash([0x44; 16]), 0x00000003),
                ],
            );

            let parsed = parse_slice_checksum(&data).unwrap();
            let Par2PacketBody::SliceChecksum(sc) = parsed else {
                panic!("Expected SliceChecksum variant");
            };

            assert_eq!(sc.entries.len(), 3);
            assert_eq!(sc.entries[0].crc32, 1);
            assert_eq!(sc.entries[1].crc32, 2);
            assert_eq!(sc.entries[2].crc32, 3);
        }

        #[test]
        fn leftover_bytes_not_divisible_by_20() {
            let mut data = build_slice_checksum_bytes(
                Par2FileId([0xAA; 16]),
                &[(Par2Md5Hash([0xBB; 16]), 0x01)],
            );
            data.extend_from_slice(&[0xFF; 7]); // 7 extra bytes — not a multiple of 20

            assert!(parse_slice_checksum(&data).is_err());
        }
    }

    mod parse_recovery_slice {
        use super::*;
        use byteorder::WriteBytesExt;
        use std::io::Write;

        #[test]
        fn exponent_and_data_split_correctly() {
            let mut cursor = Cursor::new(Vec::new());
            cursor.write_u32::<LittleEndian>(42).unwrap();
            cursor.write_all(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
            let data = cursor.into_inner();

            let parsed = parse_recovery_slice(&data).unwrap();
            let Par2PacketBody::RecoverySlice(rs) = parsed else {
                panic!("Expected RecoverySlice variant");
            };

            assert_eq!(rs.exponent, 42);
            assert_eq!(rs.recovery_data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        }
    }

    mod parse_creator {
        use super::*;

        #[test]
        fn name_with_null_padding() {
            // "par2 test 1.0" (11 bytes) + 1 null byte for 4-byte alignment
            let mut data = b"par2 test 1.0".to_vec();
            data.push(0x00);

            let parsed = parse_creator(&data).unwrap();
            let Par2PacketBody::Creator(creator) = parsed else {
                panic!("Expected Creator variant");
            };

            assert_eq!(creator.name, b"par2 test 1.0");
        }
    }

    mod find_next_header_offset {
        use super::*;

        #[test]
        fn magic_bytes_at_start() {
            assert_eq!(find_next_header_offset(PAR2_PACKET_MAGIC_HEADER), Some(0));
        }

        #[test]
        fn magic_bytes_at_end() {
            let mut data = vec![0x10, 0x11, 0x12];
            data.extend_from_slice(PAR2_PACKET_MAGIC_HEADER);
            assert_eq!(find_next_header_offset(&data), Some(3));
        }

        #[test]
        fn multiple_returns_first() {
            let mut data = vec![0x10, 0x11];
            data.extend_from_slice(PAR2_PACKET_MAGIC_HEADER);
            data.extend_from_slice(&[0x12]);
            data.extend_from_slice(PAR2_PACKET_MAGIC_HEADER);
            assert_eq!(find_next_header_offset(&data), Some(2));
        }

        #[test]
        fn no_magic_returns_none() {
            assert_eq!(find_next_header_offset(b"PAR3\0PKT"), None);
        }

        #[test]
        fn half_magic_returns_none() {
            assert_eq!(
                find_next_header_offset(&PAR2_PACKET_MAGIC_HEADER[0..4]),
                None
            );
        }

        #[test]
        fn empty_data_returns_none() {
            assert_eq!(find_next_header_offset(&[]), None);
        }
    }

    mod trim_trailing_null_bytes {
        use super::*;

        #[test]
        fn empty_input() {
            assert_eq!(trim_trailing_null_bytes(&[]), Vec::new());
        }

        #[test]
        fn all_null_bytes() {
            assert_eq!(trim_trailing_null_bytes(&[0; 5]), Vec::new());
        }

        #[test]
        fn no_null_bytes() {
            assert_eq!(
                trim_trailing_null_bytes(&[0x10, 0x11, 0x12]),
                vec![0x10, 0x11, 0x12]
            );
        }

        #[test]
        fn only_trailing_null_bytes() {
            assert_eq!(
                trim_trailing_null_bytes(&[0x10, 0, 0x12, 0x13, 0, 0]),
                vec![0x10, 0, 0x12, 0x13]
            );
        }

        #[test]
        fn single_byte_with_trailing() {
            assert_eq!(trim_trailing_null_bytes(&[0x41, 0x00, 0x00]), vec![0x41]);
        }
    }
}
