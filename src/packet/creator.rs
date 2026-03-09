use crate::error::Par2Error;

use super::trim_trailing_null_bytes;

#[derive(Debug)]
pub struct Par2CreatorData {
    pub(crate) name: String,
}

impl Par2CreatorData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let name_bytes = trim_trailing_null_bytes(data);
        let name = match String::from_utf8(name_bytes.to_vec()) {
            Ok(name) => name,
            Err(_) => {
                return Err(Par2Error::ParseError(
                    "creator name is not valid utf-8".to_string(),
                ));
            }
        };

        Ok(Par2CreatorData { name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_with_null_padding() {
        // "par2 test 1.0" (11 bytes) + 1 null byte for 4-byte alignment
        let data = b"par2 test 1.0\0".to_vec();

        let creator = Par2CreatorData::from_bytes(&data).unwrap();

        assert_eq!(creator.name, "par2 test 1.0");
    }
}
