use super::{
    PAR2_HASH_START_OFFSET, PAR2_HEADER_SIZE, PAR2_PACKET_MAGIC_HEADER, Par2Md5Hash,
    Par2PacketType, Par2RecoverySetId,
};
use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use md5::{Digest, Md5};
use std::io::{Cursor, Read, Write};

pub struct Par2PacketHeader {
    pub(crate) packet_length: u64,
    pub(crate) expected_md5: Par2Md5Hash,
    pub(crate) computed_md5: Par2Md5Hash,
    pub(crate) recovery_set_id: Par2RecoverySetId,
    pub(crate) packet_type: Par2PacketType,
}

impl Par2PacketHeader {
    pub fn from_body(
        recovery_set_id: &Par2RecoverySetId,
        packet_type: &Par2PacketType,
        body_data: &[u8],
    ) -> Self {
        let packet_length = (PAR2_HEADER_SIZE + body_data.len()) as u64;

        let mut hasher = Md5::new();

        hasher.update(recovery_set_id.as_ref());
        hasher.update(packet_type.as_ref());
        hasher.update(body_data);

        let computed_md5 = Par2Md5Hash(hasher.finalize().into());

        Par2PacketHeader {
            computed_md5,
            expected_md5: computed_md5,
            packet_length,
            packet_type: *packet_type,
            recovery_set_id: *recovery_set_id,
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let mut magic_bytes = [0; PAR2_PACKET_MAGIC_HEADER.len()];
        cursor.read_exact(&mut magic_bytes)?;

        if magic_bytes != PAR2_PACKET_MAGIC_HEADER {
            return Err(Par2Error::ParseError(format!(
                "invalid magic bytes: {:?}",
                magic_bytes
            )));
        }

        let packet_length = cursor
            .read_u64::<LittleEndian>()
            .map_err(|e| Par2Error::ParseError(format!("truncated packet length: {}", e)))?;

        let mut expected_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
        cursor
            .read_exact(expected_md5.as_mut())
            .map_err(|e| Par2Error::ParseError(format!("truncated md5: {}", e)))?;

        let mut recovery_set_id: Par2RecoverySetId = Par2RecoverySetId([0; 16]);
        cursor
            .read_exact(recovery_set_id.as_mut())
            .map_err(|e| Par2Error::ParseError(format!("truncated recovery set id: {}", e)))?;

        let mut packet_type: Par2PacketType = [0; 16];
        cursor
            .read_exact(&mut packet_type)
            .map_err(|e| Par2Error::ParseError(format!("truncated packet type: {}", e)))?;

        // The packet length must be large enough to contain the entire header.
        if packet_length < PAR2_HEADER_SIZE as u64 {
            return Err(Par2Error::ParseError(format!(
                "packet length {} is less than minimum {}",
                packet_length, PAR2_HEADER_SIZE,
            )));
        }

        let header_hash_start_position = PAR2_HASH_START_OFFSET;
        let header_hash_end_position = packet_length as usize;
        let data_size = data.len();

        if header_hash_end_position > data_size {
            return Err(Par2Error::ParseError(format!(
                "packet length {} exceeds available data {}",
                header_hash_end_position, data_size
            )));
        }

        let computed_md5 = Par2Md5Hash(
            Md5::digest(&data[header_hash_start_position..header_hash_end_position]).into(),
        );

        Ok(Par2PacketHeader {
            packet_length,
            expected_md5,
            computed_md5,
            recovery_set_id,
            packet_type,
        })
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Par2Error> {
        let mut cursor = Cursor::new(Vec::new());

        cursor.write_all(PAR2_PACKET_MAGIC_HEADER)?;
        cursor.write_u64::<LittleEndian>(self.packet_length)?;
        cursor.write_all(self.expected_md5.as_ref())?;
        cursor.write_all(self.recovery_set_id.as_ref())?;
        cursor.write_all(&self.packet_type)?;

        Ok(cursor.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    fn build_header_bytes(
        packet_length: u64,
        expected_md5: Par2Md5Hash,
        recovery_set_id: Par2RecoverySetId,
        packet_type: Par2PacketType,
        magic_bytes: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());

        cursor
            .write_all(magic_bytes.unwrap_or(PAR2_PACKET_MAGIC_HEADER))
            .unwrap();
        cursor.write_u64::<LittleEndian>(packet_length).unwrap();
        cursor.write_all(expected_md5.as_ref()).unwrap();
        cursor.write_all(recovery_set_id.as_ref()).unwrap();
        cursor.write_all(packet_type.as_ref()).unwrap();

        // Pad to at least packet_length bytes so the MD5 computation has enough data
        let mut data = cursor.into_inner();
        let min_size = packet_length as usize;
        if data.len() < min_size {
            data.resize(min_size, 0);
        }

        data
    }

    #[test]
    fn parses_header() {
        let header_bytes = build_header_bytes(
            64,
            Par2Md5Hash([0xAA; 16]),
            Par2RecoverySetId([0xBB; 16]),
            [0xCC; 16],
            None,
        );

        let parsed_header = Par2PacketHeader::from_bytes(&header_bytes).unwrap();

        assert_eq!(parsed_header.packet_length, 64);
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

        assert!(Par2PacketHeader::from_bytes(truncated).is_err());
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

        assert!(Par2PacketHeader::from_bytes(truncated).is_err());
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

        assert!(Par2PacketHeader::from_bytes(&header_bytes).is_err());
    }
}
