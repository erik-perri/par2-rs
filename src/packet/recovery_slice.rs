use crate::error::Par2Error;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct Par2RecoverySliceData {
    pub(crate) exponent: u32,
    pub(crate) recovery_data: Vec<u8>,
}

impl Par2RecoverySliceData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Par2Error> {
        let mut cursor = Cursor::new(data);

        let exponent = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Par2Error::ParseError(format!("truncated recovery slice exponent: {}", e))
        })?;

        let slice_size = cursor.get_ref().len() - cursor.position() as usize;
        let mut recovery_data = Vec::with_capacity(slice_size);

        cursor
            .read_to_end(&mut recovery_data)
            .map_err(|e| Par2Error::ParseError(format!("truncated recovery slice data: {}", e)))?;

        Ok(Par2RecoverySliceData {
            exponent,
            recovery_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    #[test]
    fn exponent_and_data_split_correctly() {
        let mut cursor = Cursor::new(Vec::new());
        cursor.write_u32::<LittleEndian>(42).unwrap();
        cursor.write_all(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        let data = cursor.into_inner();

        let rs = Par2RecoverySliceData::from_bytes(&data).unwrap();

        assert_eq!(rs.exponent, 42);
        assert_eq!(rs.recovery_data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
