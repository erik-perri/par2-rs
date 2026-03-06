pub enum Par2Error {
    DuplicateMainPacket,
    FilePathError(String),
    Io(std::io::Error),
    MissingComputedMD5,
    MissingFileDescriptions,
    MissingMainPacket,
    MissingRecoverySetId,
    MissingSliceChecksums,
    ParseError(String),
}

impl From<std::io::Error> for Par2Error {
    fn from(err: std::io::Error) -> Self {
        Par2Error::Io(err)
    }
}

impl From<std::str::Utf8Error> for Par2Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Par2Error::ParseError(format!("Invalid UTF-8 encoding: {}", err))
    }
}

impl std::fmt::Display for Par2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2Error::DuplicateMainPacket => write!(f, "Duplicate main packet"),
            Par2Error::FilePathError(message) => write!(f, "File path error: {}", message),
            Par2Error::Io(err) => write!(f, "IO error: {}", err),
            Par2Error::MissingComputedMD5 => write!(f, "Missing computed MD5"),
            Par2Error::MissingFileDescriptions => write!(f, "Missing file descriptions"),
            Par2Error::MissingMainPacket => write!(f, "Missing main packet"),
            Par2Error::MissingRecoverySetId => write!(f, "Missing recovery set ID"),
            Par2Error::MissingSliceChecksums => write!(f, "Missing slice checksums"),
            Par2Error::ParseError(message) => write!(f, "Parse error: {}", message),
        }
    }
}

#[derive(Debug)]
pub enum Par2Warning {
    MissingCreator,
    UnknownPacketType,
}

impl std::fmt::Display for Par2Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2Warning::MissingCreator => write!(f, "Missing creator"),
            Par2Warning::UnknownPacketType => write!(f, "Unknown packet type"),
        }
    }
}
