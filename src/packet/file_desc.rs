use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

use super::{Par2FileId, Par2Md5Hash, trim_trailing_null_bytes};

#[derive(Debug, Eq, PartialEq)]
pub struct Par2FileDescriptionData {
    pub(crate) file_id: Par2FileId,
    pub(crate) file_md5: Par2Md5Hash,
    pub(crate) file_first_16kb_md5: Par2Md5Hash,
    pub(crate) file_length: u64,
    pub(crate) file_name: String,
}

impl Par2FileDescriptionData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let mut file_id: Par2FileId = Par2FileId([0; 16]);
        cursor.read_exact(file_id.as_mut()).map_err(|e| {
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

        Ok(Par2FileDescriptionData {
            file_id,
            file_md5,
            file_first_16kb_md5,
            file_length,
            file_name,
        })
    }
}

#[cfg(test)]
mod tests {
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

        let file_desc = Par2FileDescriptionData::from_bytes(&file_description_bytes).unwrap();

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

        let file_desc = Par2FileDescriptionData::from_bytes(&file_description_bytes).unwrap();

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

        let file_desc = Par2FileDescriptionData::from_bytes(&file_description_bytes).unwrap();

        assert_eq!(file_desc.file_name, "testtxt");
    }

    #[test]
    fn too_short() {
        let file_description_bytes = [0xAA; 32];

        let parsed_body = Par2FileDescriptionData::from_bytes(&file_description_bytes);

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

        let parsed_body = Par2FileDescriptionData::from_bytes(&file_description_bytes);

        assert!(parsed_body.is_err());
        assert!(matches!(parsed_body, Err(Par2Error::ParseError(_))));
    }
}
