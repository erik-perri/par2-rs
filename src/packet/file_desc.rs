use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use md5::{Digest, Md5};
use std::io::{Cursor, Read, Write};

use super::{Par2FileId, Par2Md5Hash, trim_trailing_null_bytes};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Par2FileDescriptionData {
    pub(crate) file_md5: Par2Md5Hash,
    pub(crate) file_first_16kb_md5: Par2Md5Hash,
    pub(crate) file_length: u64,
    pub(crate) file_name: String,
}

impl Par2FileDescriptionData {
    pub(crate) fn file_id(&self) -> Par2FileId {
        let mut hasher = Md5::new();

        hasher.update(self.file_first_16kb_md5.as_ref());
        hasher.update(self.file_length.to_le_bytes());
        hasher.update(self.file_name.as_bytes());

        let computed_file_id = Par2Md5Hash(hasher.finalize().into());
        Par2FileId::from(computed_file_id)
    }

    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let mut file_id = [0u8; 16];
        cursor.read_exact(&mut file_id).map_err(|e| {
            Par2Error::ParseError(format!("truncated file description file id: {}", e))
        })?;

        let mut file_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
        cursor
            .read_exact(file_md5.as_mut())
            .map_err(|e| Par2Error::ParseError(format!("truncated file description md5: {}", e)))?;

        let mut file_first_16kb_md5: Par2Md5Hash = Par2Md5Hash([0; 16]);
        cursor
            .read_exact(file_first_16kb_md5.as_mut())
            .map_err(|e| {
                Par2Error::ParseError(format!("truncated file description first 16kb md5: {}", e))
            })?;

        let file_length = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Par2Error::ParseError(format!("truncated file description length: {}", e))
        })?;

        let mut parsed_name = vec![0; data.len() - cursor.position() as usize];
        cursor.read_exact(&mut parsed_name).map_err(|e| {
            Par2Error::ParseError(format!("truncated file description name: {}", e))
        })?;

        let file_name_bytes = trim_trailing_null_bytes(&parsed_name);
        let file_name = match String::from_utf8(file_name_bytes.to_vec()) {
            Ok(name) => name,
            Err(_) => {
                return Err(Par2Error::ParseError(
                    "file description name is not valid utf-8".to_string(),
                ));
            }
        };

        let parsed_data = Par2FileDescriptionData {
            file_md5,
            file_first_16kb_md5,
            file_length,
            file_name,
        };

        if parsed_data.file_id().as_ref() != file_id {
            return Err(Par2Error::ParseError(
                "file id in header does not match computed file id".to_string(),
            ));
        }

        Ok(parsed_data)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Par2Error> {
        let file_id = self.file_id();

        let mut cursor = Cursor::new(Vec::new());

        cursor.write_all(file_id.as_ref())?;
        cursor.write_all(self.file_md5.as_ref())?;
        cursor.write_all(self.file_first_16kb_md5.as_ref())?;
        cursor.write_u64::<LittleEndian>(self.file_length)?;

        let name_bytes = self.file_name.as_bytes();
        cursor.write_all(name_bytes)?;

        let padding_length = (4 - (name_bytes.len() % 4)) % 4;
        let padding = vec![0u8; padding_length];
        cursor.write_all(&padding)?;

        Ok(cursor.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_file_description() {
        let expected = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0xBB; 16]),
            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
            file_length: 1234,
            file_name: "a.txt".to_string(),
        };

        let body_bytes = expected.to_bytes().unwrap();
        let file_desc = Par2FileDescriptionData::from_bytes(&body_bytes).unwrap();

        assert_eq!(file_desc, expected);
    }

    #[test]
    fn no_name_padding() {
        let expected = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0xBB; 16]),
            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
            file_length: 1234,
            // "test.txt" is exactly 8 bytes, so it requires no padding
            file_name: "test.txt".to_string(),
        };

        let body_bytes = expected.to_bytes().unwrap();
        let file_desc = Par2FileDescriptionData::from_bytes(&body_bytes).unwrap();

        assert_eq!(file_desc, expected);
    }

    #[test]
    fn minimal_name_padding() {
        let expected = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0xBB; 16]),
            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
            file_length: 1234,
            // "testtxt" is 7 bytes, so it requires 1 byte of padding
            file_name: "testtxt".to_string(),
        };

        let body_bytes = expected.to_bytes().unwrap();
        let file_desc = Par2FileDescriptionData::from_bytes(&body_bytes).unwrap();

        assert_eq!(file_desc, expected);
    }

    #[test]
    fn too_short() {
        // 32 bytes is less than the 56 required for the headers before the name
        let body_bytes = [0xAA; 32];
        let parsed_body = Par2FileDescriptionData::from_bytes(&body_bytes);

        assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
    }

    #[test]
    fn invalid_name() {
        let mut body_bytes = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0xBB; 16]),
            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
            file_length: 1234,
            file_name: "a.txt".to_string(),
        }
        .to_bytes()
        .unwrap();

        // The file name starts at offset 56 (16 id + 16 md5 + 16 md5_16k + 8 length).
        // Overwrite the 5 bytes of "a.txt" with invalid UTF-8.
        body_bytes[56..61].copy_from_slice(&[0xFF; 5]);

        let parsed_body = Par2FileDescriptionData::from_bytes(&body_bytes);
        assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
    }

    #[test]
    fn mismatched_file_id() {
        let mut body_bytes = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0xCC; 16]),
            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
            file_length: 1234,
            file_name: "a.txt".to_string(),
        }
        .to_bytes()
        .unwrap();

        // Overwrite the prepended file_id (the first 16 bytes) with something incorrect
        body_bytes[0..16].copy_from_slice(&[0xFF; 16]);

        let parsed_body = Par2FileDescriptionData::from_bytes(&body_bytes);
        assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
    }

    #[test]
    fn to_bytes_matches_specification() {
        let description = Par2FileDescriptionData {
            file_md5: Par2Md5Hash([0x11; 16]),
            file_first_16kb_md5: Par2Md5Hash([0x22; 16]),
            file_length: 258, // 0x0102 in hex
            file_name: "a.txt".to_string(),
        };

        let bytes = description.to_bytes().unwrap();

        // 16 bytes for File ID (Computed internally by MD5, so we just check length/existence here,
        // or calculate the exact expected MD5 hash of "a.txt" + length + 16k hash)
        let expected_file_id = description.file_id();

        let mut expected_bytes = Vec::new();

        // 16 bytes
        expected_bytes.extend_from_slice(expected_file_id.as_ref());

        // 16 bytes (file_md5)
        expected_bytes.extend_from_slice(&[0x11; 16]);

        // 16 bytes (first 16k md5)
        expected_bytes.extend_from_slice(&[0x22; 16]);

        // 8 bytes (LittleEndian 258)
        expected_bytes.extend_from_slice(&[0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // 5 bytes (Name)
        expected_bytes.extend_from_slice(b"a.txt");

        // 3 bytes (Padding to multiple of 4)
        expected_bytes.extend_from_slice(&[0x00, 0x00, 0x00]);

        assert_eq!(bytes, expected_bytes);
    }
}
