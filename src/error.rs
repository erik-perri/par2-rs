use crate::packet::{Par2FileId, Par2Md5Hash, Par2PacketType, Par2RecoverySetId};

#[derive(Debug)]
pub enum Par2Error {
    AllFileDescriptionsCorrupt,
    AllSliceChecksumsCorrupt,
    DuplicateInputFile,
    FilePathError(String),
    InvalidMainPacket(String),
    InvalidPacket,
    Io(std::io::Error),
    MainPacketConflict,
    MainPacketIntegrityFailure,
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
        Par2Error::ParseError(format!("invalid utf-8: {}", err))
    }
}

impl std::fmt::Display for Par2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2Error::AllFileDescriptionsCorrupt => write!(f, "all file descriptions are corrupt"),
            Par2Error::AllSliceChecksumsCorrupt => write!(f, "all slice checksums are corrupt"),
            Par2Error::DuplicateInputFile => write!(f, "duplicate input file"),
            Par2Error::FilePathError(message) => write!(f, "{}", message),
            Par2Error::InvalidMainPacket(message) => write!(f, "invalid main packet: {}", message),
            Par2Error::InvalidPacket => write!(f, "invalid packet type"),
            Par2Error::Io(err) => write!(f, "{}", err),
            Par2Error::MainPacketConflict => write!(f, "conflicting main packet"),
            Par2Error::MainPacketIntegrityFailure => write!(f, "main packet integrity failure"),
            Par2Error::MissingFileDescriptions => write!(f, "missing file descriptions"),
            Par2Error::MissingMainPacket => write!(f, "missing main packet"),
            Par2Error::MissingSliceChecksums => write!(f, "missing slice checksums"),
            Par2Error::ParseError(message) => write!(f, "{}", message),
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
    IntegrityFailure(Par2WarningDataType, Par2Md5Hash, Par2Md5Hash),
    MissingCreator,
    UnexpectedFileDescription(Par2FileId),
    UnexpectedRecoverySetId(Par2WarningDataType, Par2RecoverySetId, Par2RecoverySetId),
    UnexpectedSliceData(Par2FileId),
    UnknownPacketType(Par2PacketType),
}

impl std::fmt::Display for Par2Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Par2Warning::AllRecoverySlicesCorrupt => write!(f, "all recovery slices are corrupt"),
            Par2Warning::IntegrityFailure(data_type, expected, actual) => {
                write!(
                    f,
                    "integrity failure for {}: expected {}, got {}",
                    data_type,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Par2Warning::MissingCreator => write!(f, "missing creator"),
            Par2Warning::UnexpectedRecoverySetId(data_type, expected, actual) => {
                write!(
                    f,
                    "mismatched recovery set id for {}: expected {}, got {}",
                    data_type,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Par2Warning::UnexpectedFileDescription(file_id) => {
                write!(
                    f,
                    "unexpected file description for file {}",
                    hex::encode(file_id)
                )
            }
            Par2Warning::UnexpectedSliceData(file_id) => {
                write!(f, "unexpected slice data for file {}", hex::encode(file_id))
            }
            Par2Warning::UnknownPacketType(packet_type) => {
                write!(f, "unknown packet type {}", hex::encode(packet_type))
            }
        }
    }
}
