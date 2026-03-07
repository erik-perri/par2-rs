use crate::packet::{Par2Md5Hash, Par2PacketType, Par2RecoverySetId};

#[derive(Debug)]
pub enum Par2Error {
    AllFileDescriptionsCorrupt,
    AllSliceChecksumsCorrupt,
    FilePathError(String),
    Io(std::io::Error),
    MainPacketConflict,
    MainPacketIntegrityFailure,
    MissingComputedMD5,
    MissingFileDescriptions,
    MissingMainPacket,
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
            Par2Error::AllFileDescriptionsCorrupt => write!(f, "All file descriptions are corrupt"),
            Par2Error::AllSliceChecksumsCorrupt => write!(f, "All slice checksums are corrupt"),
            Par2Error::FilePathError(message) => write!(f, "File path error: {}", message),
            Par2Error::Io(err) => write!(f, "IO error: {}", err),
            Par2Error::MainPacketConflict => {
                write!(f, "A conflicting main packet was found")
            }
            Par2Error::MainPacketIntegrityFailure => write!(f, "Main packet integrity failure"),
            Par2Error::MissingComputedMD5 => write!(f, "Missing computed MD5"),
            Par2Error::MissingFileDescriptions => write!(f, "Missing file descriptions"),
            Par2Error::MissingMainPacket => write!(f, "Missing main packet"),
            Par2Error::MissingSliceChecksums => write!(f, "Missing slice checksums"),
            Par2Error::ParseError(message) => write!(f, "Parse error: {}", message),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Par2WarningDataType {
    FileDescription,
    SliceChecksum,
    RecoverySlice,
    Creator,
}

impl std::fmt::Display for Par2WarningDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2WarningDataType::FileDescription => write!(f, "file description"),
            Par2WarningDataType::SliceChecksum => write!(f, "slice checksum"),
            Par2WarningDataType::RecoverySlice => write!(f, "recovery slice"),
            Par2WarningDataType::Creator => write!(f, "creator"),
        }
    }
}

#[derive(Debug)]
pub enum Par2Warning {
    AllRecoverySlicesCorrupt,
    MissingCreator,
    IntegrityFailure(Par2WarningDataType, Par2Md5Hash, Par2Md5Hash),
    UnexpectedRecoverySetId(Par2WarningDataType, Par2RecoverySetId, Par2RecoverySetId),
    UnknownPacketType(Par2PacketType),
}

impl std::fmt::Display for Par2Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2Warning::AllRecoverySlicesCorrupt => write!(f, "All recovery slices are corrupt"),
            Par2Warning::MissingCreator => write!(f, "Missing creator"),
            Par2Warning::IntegrityFailure(data_type, expected, actual) => {
                write!(
                    f,
                    "Integrity failure for {}: expected {}, actual {}",
                    data_type,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Par2Warning::UnexpectedRecoverySetId(data_type, expected, actual) => {
                write!(
                    f,
                    "Mismatched recovery set ID for {}: expected {}, actual {}",
                    data_type,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Par2Warning::UnknownPacketType(packet_type) => {
                write!(f, "Unknown packet type {}", hex::encode(packet_type))
            }
        }
    }
}
