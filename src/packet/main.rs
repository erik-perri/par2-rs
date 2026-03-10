use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use md5::{Digest, Md5};
use std::io::{Cursor, Read, Write};

use super::{Par2FileId, Par2Md5Hash, Par2RecoverySetId};

#[derive(Debug)]
pub struct Par2MainData {
    pub(crate) non_recovery_file_ids: Vec<Par2FileId>,
    pub(crate) recovery_file_ids: Vec<Par2FileId>,
    pub(crate) slice_size: u64,
}

impl Par2MainData {
    pub fn recovery_set_id(&self) -> Par2RecoverySetId {
        let mut hasher = Md5::new();

        hasher.update(self.slice_size.to_le_bytes());
        hasher.update((self.recovery_file_ids.len() as u32).to_le_bytes());

        for recovery_file_id in &self.recovery_file_ids {
            hasher.update(recovery_file_id.as_ref());
        }

        for non_recovery_file_id in &self.non_recovery_file_ids {
            hasher.update(non_recovery_file_id.as_ref());
        }

        let computed_md5 = Par2Md5Hash(hasher.finalize().into());
        Par2RecoverySetId::from(computed_md5)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let slice_size = cursor
            .read_u64::<LittleEndian>()
            .map_err(|e| Par2Error::ParseError(format!("truncated slice size: {}", e)))?;

        let file_count = cursor
            .read_u32::<LittleEndian>()
            .map_err(|e| Par2Error::ParseError(format!("truncated file count: {}", e)))?;

        let required_bytes = (file_count as u64).saturating_mul(16);
        let remaining_bytes = cursor.get_ref().len() as u64 - cursor.position();

        if required_bytes > remaining_bytes {
            return Err(Par2Error::ParseError(format!(
                "file count {} exceeds available data",
                file_count
            )));
        }

        let mut recovery_file_ids = Vec::with_capacity(file_count as usize);

        for _ in 0..file_count {
            let mut file_id: Par2FileId = Par2FileId([0; 16]);

            cursor
                .read_exact(file_id.as_mut())
                .map_err(|e| Par2Error::ParseError(format!("truncated file id: {}", e)))?;

            recovery_file_ids.push(file_id);
        }

        let remaining_bytes = cursor.get_ref().len() as u64 - cursor.position();
        if !remaining_bytes.is_multiple_of(16) {
            return Err(Par2Error::ParseError(format!(
                "{} trailing bytes after recovery file ids, expected multiple of 16",
                remaining_bytes
            )));
        }

        let non_recovery_file_count = remaining_bytes / 16;
        let mut non_recovery_file_ids = Vec::with_capacity(non_recovery_file_count as usize);

        for _ in 0..non_recovery_file_count {
            let mut file_id: Par2FileId = Par2FileId([0; 16]);
            cursor.read_exact(file_id.as_mut()).map_err(|e| {
                Par2Error::ParseError(format!("truncated non-recovery file id: {}", e))
            })?;

            non_recovery_file_ids.push(file_id);
        }

        Ok(Par2MainData {
            non_recovery_file_ids,
            recovery_file_ids,
            slice_size,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Par2Error> {
        let capacity =
            8 + 4 + (self.recovery_file_ids.len() * 16) + (self.non_recovery_file_ids.len() * 16);
        let mut cursor = Cursor::new(Vec::with_capacity(capacity));

        cursor.write_u64::<LittleEndian>(self.slice_size)?;
        cursor.write_u32::<LittleEndian>(self.recovery_file_ids.len() as u32)?;

        for recovery_file_id in &self.recovery_file_ids {
            cursor.write_all(recovery_file_id.as_ref())?;
        }

        for non_recovery_file_id in &self.non_recovery_file_ids {
            cursor.write_all(non_recovery_file_id.as_ref())?;
        }

        Ok(cursor.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_body() {
        let expected = Par2MainData {
            slice_size: 1234,
            recovery_file_ids: vec![Par2FileId([0xAA; 16]), Par2FileId([0xBB; 16])],
            non_recovery_file_ids: vec![],
        };

        let body_bytes = expected.to_bytes().unwrap();
        let main_data = Par2MainData::from_bytes(&body_bytes).unwrap();

        assert_eq!(main_data.slice_size, expected.slice_size);
        assert_eq!(main_data.recovery_file_ids, expected.recovery_file_ids);
        assert_eq!(
            main_data.non_recovery_file_ids,
            expected.non_recovery_file_ids
        );
    }

    #[test]
    fn non_recovery_files() {
        let expected = Par2MainData {
            slice_size: 1234,
            recovery_file_ids: vec![],
            non_recovery_file_ids: vec![Par2FileId([0xCC; 16])],
        };

        let body_bytes = expected.to_bytes().unwrap();
        let main_data = Par2MainData::from_bytes(&body_bytes).unwrap();

        assert_eq!(main_data.slice_size, expected.slice_size);
        assert_eq!(main_data.recovery_file_ids, expected.recovery_file_ids);
        assert_eq!(
            main_data.non_recovery_file_ids,
            expected.non_recovery_file_ids
        );
    }

    #[test]
    fn invalid_file_count() {
        let mut body_bytes = Par2MainData {
            slice_size: 1234,
            recovery_file_ids: vec![],
            non_recovery_file_ids: vec![],
        }
        .to_bytes()
        .unwrap();

        // The file_count sits at offset 8 (after 8 bytes of slice_size).
        // Overwrite it with a higher value (10) to exceed available bounds.
        body_bytes[8..12].copy_from_slice(&10u32.to_le_bytes());

        assert!(Par2MainData::from_bytes(&body_bytes).is_err());
    }

    #[test]
    fn unexpected_size() {
        let body_bytes = Par2MainData {
            slice_size: 1234,
            recovery_file_ids: vec![Par2FileId([0xCC; 16])],
            non_recovery_file_ids: vec![Par2FileId([0xBB; 16])],
        }
        .to_bytes()
        .unwrap();

        // Truncate the last 4 bytes to cause a length validation error
        let truncated = &body_bytes[0..body_bytes.len() - 4];

        assert!(Par2MainData::from_bytes(truncated).is_err());
    }

    #[test]
    fn to_bytes_matches_specification() {
        let main_data = Par2MainData {
            slice_size: 258, // 0x0102 in hex
            recovery_file_ids: vec![Par2FileId([0x11; 16])],
            non_recovery_file_ids: vec![Par2FileId([0x22; 16])],
        };

        let bytes = main_data.to_bytes().unwrap();

        let mut expected_bytes = Vec::new();

        // 8 bytes: slice_size (LittleEndian 258)
        expected_bytes.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // 4 bytes: recovery file count (LittleEndian 1)
        expected_bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // 16 bytes: the single recovery_file_id
        expected_bytes.extend_from_slice(&[0x11; 16]);

        // 16 bytes: the single non_recovery_file_id
        // (Notice there is no count for non-recovery files, the spec
        // determines them purely by the remaining length of the packet)
        expected_bytes.extend_from_slice(&[0x22; 16]);

        assert_eq!(bytes, expected_bytes);
    }
}
