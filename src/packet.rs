mod creator;
mod file_desc;
mod header;
mod main;
mod recovery_slice;
mod slice_checksum;

pub use creator::Par2CreatorData;
pub use file_desc::Par2FileDescriptionData;
pub use header::Par2PacketHeader;
pub use main::Par2MainData;
pub use recovery_slice::Par2RecoverySliceData;
pub use slice_checksum::{Par2SliceChecksumData, Par2SliceChecksumEntry};

use crate::error::Par2Error;
use log::debug;
use std::fmt::Display;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Par2FileId(pub(crate) [u8; 16]);

impl std::fmt::Debug for Par2FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Par2FileId({})", hex::encode(self.0))
    }
}

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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Par2Md5Hash(pub(crate) [u8; 16]);

impl std::fmt::Debug for Par2Md5Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Par2Md5Hash({})", hex::encode(self.0))
    }
}

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

#[derive(Clone, Copy, Eq, PartialEq)]
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

impl std::fmt::Debug for Par2RecoverySetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Par2RecoverySetId({})", hex::encode(self.0))
    }
}

pub type Par2PacketType = [u8; 16];

pub struct Par2Packet {
    pub(crate) header: Par2PacketHeader,
    pub(crate) body: Par2PacketBody,
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

impl Par2PacketBody {
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Par2Error> {
        match self {
            Par2PacketBody::Main(data) => data.to_bytes(),
            Par2PacketBody::FileDesc(data) => data.to_bytes(),
            Par2PacketBody::SliceChecksum(data) => data.to_bytes(),
            Par2PacketBody::RecoverySlice(data) => data.to_bytes(),
            Par2PacketBody::Creator(data) => data.to_bytes(),
            Par2PacketBody::Unknown(..) => Err(Par2Error::InvalidPacket),
        }
    }

    pub(crate) fn packet_type(&self) -> &Par2PacketType {
        match self {
            Par2PacketBody::Main(..) => PAR2_PACKET_MAGIC_MAIN,
            Par2PacketBody::FileDesc(..) => PAR2_PACKET_MAGIC_FILE_DESC,
            Par2PacketBody::SliceChecksum(..) => PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
            Par2PacketBody::RecoverySlice(..) => PAR2_PACKET_MAGIC_RECOVERY_SLICE,
            Par2PacketBody::Creator(..) => PAR2_PACKET_MAGIC_CREATOR,
            Par2PacketBody::Unknown(packet_type) => packet_type,
        }
    }
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

        let header = Par2PacketHeader::from_bytes(&file_data[header_offset..]).map_err(|e| {
            Par2Error::ParseError(format!("invalid header at offset {}: {}", header_offset, e))
        })?;

        let packet_length = header.packet_length as usize;

        debug!(
            "Parsed header {} at [{}], length {}",
            display_packet_type(&header.packet_type),
            header_offset,
            packet_length
        );

        let body_offset = header_offset + PAR2_HEADER_SIZE;
        let body_bytes = &file_data[body_offset..header_offset + packet_length];

        let body = parse_body(&header.packet_type, body_bytes).map_err(|e| {
            Par2Error::ParseError(format!("invalid body at offset {}: {}", header_offset, e))
        })?;

        debug!(
            "Parsed body at [{}], length {}",
            body_offset,
            body_bytes.len()
        );

        packets.push(Par2Packet { header, body });

        // Move to the next packet
        offset = header_offset + packet_length;
    }

    Ok(packets)
}

fn display_packet_type(packet_type: &Par2PacketType) -> String {
    String::from_utf8_lossy(packet_type.as_ref()).replace('\0', "_")
}

fn parse_body(packet_type: &Par2PacketType, data: &[u8]) -> Result<Par2PacketBody, Par2Error> {
    match packet_type {
        PAR2_PACKET_MAGIC_MAIN => Ok(Par2PacketBody::Main(Par2MainData::from_bytes(data)?)),
        PAR2_PACKET_MAGIC_FILE_DESC => Ok(Par2PacketBody::FileDesc(
            Par2FileDescriptionData::from_bytes(data)?,
        )),
        PAR2_PACKET_MAGIC_SLICE_CHECKSUM => Ok(Par2PacketBody::SliceChecksum(
            Par2SliceChecksumData::from_bytes(data)?,
        )),
        PAR2_PACKET_MAGIC_RECOVERY_SLICE => Ok(Par2PacketBody::RecoverySlice(
            Par2RecoverySliceData::from_bytes(data)?,
        )),
        PAR2_PACKET_MAGIC_CREATOR => {
            Ok(Par2PacketBody::Creator(Par2CreatorData::from_bytes(data)?))
        }
        _ => Ok(Par2PacketBody::Unknown(*packet_type)),
    }
}

fn find_next_header_offset(data: &[u8]) -> Option<usize> {
    data.windows(PAR2_PACKET_MAGIC_HEADER.len())
        .position(|w| w == PAR2_PACKET_MAGIC_HEADER)
}

fn trim_trailing_null_bytes(data: &[u8]) -> &[u8] {
    let last_non_null_byte = data.iter().rposition(|&b| b != 0);

    if let Some(last_non_null_byte) = last_non_null_byte {
        return &data[..last_non_null_byte + 1];
    }

    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let body_bytes = Par2FileDescriptionData {
                file_md5: Par2Md5Hash([0; 16]),
                file_first_16kb_md5: Par2Md5Hash([0; 16]),
                file_length: 0,
                file_name: "test".to_string(),
            }
            .to_bytes()
            .unwrap();

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
