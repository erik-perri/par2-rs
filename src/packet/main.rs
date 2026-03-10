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

    pub fn to_bytes(&self) -> Result<(Vec<u8>, Par2RecoverySetId), Par2Error> {
        let mut cursor = Cursor::new(Vec::new());

        cursor.write_u64::<LittleEndian>(self.slice_size)?;
        cursor.write_u32::<LittleEndian>(self.recovery_file_ids.len() as u32)?;

        for recovery_file_id in &self.recovery_file_ids {
            cursor.write_all(recovery_file_id.as_ref())?;
        }

        for non_recovery_file_id in &self.non_recovery_file_ids {
            cursor.write_all(non_recovery_file_id.as_ref())?;
        }

        let data = cursor.into_inner();

        let body_md5 = Par2Md5Hash(Md5::digest(&data).into());
        let computed_recovery_set_id = Par2RecoverySetId::from(body_md5);

        Ok((data, computed_recovery_set_id))
    }
}

#[cfg(test)]
mod tests {
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

        let main_data = Par2MainData::from_bytes(&body_bytes).unwrap();

        assert_eq!(main_data.slice_size, 1234);
        assert_eq!(main_data.recovery_file_ids.len(), 2);
        assert_eq!(main_data.recovery_file_ids[0], Par2FileId([0xAA; 16]));
        assert_eq!(main_data.recovery_file_ids[1], Par2FileId([0xBB; 16]));

        assert_eq!(main_data.non_recovery_file_ids.len(), 0);
    }

    #[test]
    fn non_recovery_files() {
        let body_bytes = build_body_main_bytes(1234, &[], &[Par2FileId([0xCC; 16])], None);

        let main_data = Par2MainData::from_bytes(&body_bytes).unwrap();

        assert_eq!(main_data.slice_size, 1234);

        assert_eq!(main_data.recovery_file_ids.len(), 0);

        assert_eq!(main_data.non_recovery_file_ids.len(), 1);
        assert_eq!(main_data.non_recovery_file_ids[0], Par2FileId([0xCC; 16]),)
    }

    #[test]
    fn invalid_file_count() {
        let body_bytes = build_body_main_bytes(1234, &[], &[], Some(10));

        assert!(Par2MainData::from_bytes(&body_bytes).is_err());
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

        assert!(Par2MainData::from_bytes(truncated).is_err());
    }
}
