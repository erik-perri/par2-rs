use crate::error::Par2Error;
use std::path::Path;

pub(crate) fn repair(_file: &Path) -> Result<(), Par2Error> {
    Err(Par2Error::ParseError("not implemented".to_string()))
}
