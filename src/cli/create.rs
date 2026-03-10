use crate::error::Par2Error;
use std::path::{Path, PathBuf};

pub(crate) fn create(
    _block_size: u64,
    _recovery_block_count: u16,
    _output: &Path,
    _files: &[PathBuf],
) -> Result<(), Par2Error> {
    Err(Par2Error::ParseError("not implemented".to_string()))
}
