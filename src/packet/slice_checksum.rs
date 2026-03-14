use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

use super::{Par2FileId, Par2Md5Hash};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Par2SliceChecksumData {
    pub(crate) file_id: Par2FileId,
    pub(crate) entries: Vec<Par2SliceChecksumEntry>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Par2SliceChecksumEntry {
    pub(crate) md5: Par2Md5Hash,
    pub(crate) crc32: u32,
}

impl Par2SliceChecksumData {
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let mut file_id: Par2FileId = Par2FileId([0; 16]);
        cursor.read_exact(file_id.as_mut()).map_err(|e| {
            Par2Error::ParseError(format!("truncated slice checksum file id: {}", e))
        })?;

        let entry_bytes = cursor.get_ref().len() - cursor.position() as usize;
        if !entry_bytes.is_multiple_of(20) {
            return Err(Par2Error::ParseError(
                "invalid slice checksum entry size".to_string(),
            ));
        }

        let entry_count = entry_bytes / 20;
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            let mut md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
            cursor.read_exact(md5.as_mut()).map_err(|e| {
                Par2Error::ParseError(format!("truncated slice checksum md5: {}", e))
            })?;

            let crc32 = cursor.read_u32::<LittleEndian>().map_err(|e| {
                Par2Error::ParseError(format!("truncated slice checksum crc32: {}", e))
            })?;

            entries.push(Par2SliceChecksumEntry { md5, crc32 });
        }

        Ok(Par2SliceChecksumData { file_id, entries })
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Par2Error> {
        let mut cursor = Cursor::new(Vec::new());

        cursor.write_all(self.file_id.as_ref())?;

        for entry in &self.entries {
            cursor.write_all(entry.md5.as_ref())?;
            cursor.write_u32::<LittleEndian>(entry.crc32)?;
        }

        Ok(cursor.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    fn build_slice_checksum_bytes(file_id: Par2FileId, entries: &[(Par2Md5Hash, u32)]) -> Vec<u8> {
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

        let sc = Par2SliceChecksumData::from_bytes(&data).unwrap();

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

        let sc = Par2SliceChecksumData::from_bytes(&data).unwrap();

        assert_eq!(sc.entries.len(), 3);
        assert_eq!(sc.entries[0].crc32, 1);
        assert_eq!(sc.entries[1].crc32, 2);
        assert_eq!(sc.entries[2].crc32, 3);
    }

    #[test]
    fn leftover_bytes_not_divisible_by_20() {
        let mut data =
            build_slice_checksum_bytes(Par2FileId([0xAA; 16]), &[(Par2Md5Hash([0xBB; 16]), 0x01)]);
        data.extend_from_slice(&[0xFF; 7]); // 7 extra bytes — not a multiple of 20

        assert!(Par2SliceChecksumData::from_bytes(&data).is_err());
    }
}
