use crate::error::{Par2Error, Par2Warning, Par2WarningDataType};
use crate::packet::{
    Par2CreatorData, Par2FileDescriptionData, Par2MainData, Par2Md5Hash, Par2Packet,
    Par2PacketBody, Par2RecoverySetId, Par2RecoverySliceData, Par2SliceChecksumData,
};

#[derive(Debug)]
struct Parsed<T> {
    recovery_set_id: Par2RecoverySetId,
    expected_md5: Par2Md5Hash,
    computed_md5: Par2Md5Hash,
    data: T,
}

#[derive(Debug)]
pub struct Par2PotentialSet {
    recovery_set_id: Par2RecoverySetId,
    main: Parsed<Par2MainData>,
    file_descriptions: Vec<Parsed<Par2FileDescriptionData>>,
    slice_checksums: Vec<Parsed<Par2SliceChecksumData>>,
    recovery_slices: Vec<Parsed<Par2RecoverySliceData>>,
    creators: Vec<Parsed<Par2CreatorData>>,
    warnings: Vec<Par2Warning>,
}

#[derive(Debug)]
pub struct Par2ValidatedSet {
    recovery_set_id: Par2RecoverySetId,
    main: Par2MainData,
    file_descriptions: Vec<Par2FileDescriptionData>,
    slice_checksums: Vec<Par2SliceChecksumData>,
    recovery_slices: Vec<Par2RecoverySliceData>,
    creators: Vec<Par2CreatorData>,
    warnings: Vec<Par2Warning>,
}

impl Par2PotentialSet {
    pub fn from_packets(packets: Vec<Par2Packet>) -> Result<Par2PotentialSet, Par2Error> {
        let mut recovery_set_id = None;
        let mut main: Option<Parsed<Par2MainData>> = None;
        let mut file_descriptions = Vec::new();
        let mut slice_checksums = Vec::new();
        let mut recovery_slices = Vec::new();
        let mut creators = Vec::new();
        let mut warnings = Vec::new();

        for packet in packets {
            let computed_md5 = packet
                .header
                .computed_md5
                .ok_or(Par2Error::MissingComputedMD5)?;

            match packet.body {
                Par2PacketBody::Main(data) => {
                    if let Some(main) = main.as_ref() {
                        if main.expected_md5 != packet.header.expected_md5
                            || main.computed_md5 != computed_md5
                            || packet.header.recovery_set_id != recovery_set_id.unwrap()
                        {
                            return Err(Par2Error::MainPacketConflict);
                        }

                        continue;
                    }

                    recovery_set_id = Some(packet.header.recovery_set_id);

                    main = Some(Parsed {
                        recovery_set_id: packet.header.recovery_set_id,
                        expected_md5: packet.header.expected_md5,
                        computed_md5,
                        data,
                    });
                }
                Par2PacketBody::FileDesc(data) => file_descriptions.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5,
                    data,
                }),
                Par2PacketBody::SliceChecksum(data) => slice_checksums.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5,
                    data,
                }),
                Par2PacketBody::RecoverySlice(data) => recovery_slices.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5,
                    data,
                }),
                Par2PacketBody::Creator(data) => creators.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5,
                    data,
                }),
                Par2PacketBody::Unknown(_) => {
                    warnings.push(Par2Warning::UnknownPacketType);
                }
            }
        }

        if creators.is_empty() {
            warnings.push(Par2Warning::MissingCreator);
        }

        if file_descriptions.is_empty() {
            return Err(Par2Error::MissingFileDescriptions);
        }

        if slice_checksums.is_empty() {
            return Err(Par2Error::MissingSliceChecksums);
        }

        Ok(Par2PotentialSet {
            recovery_set_id: recovery_set_id.ok_or(Par2Error::MissingRecoverySetId)?,
            main: main.ok_or(Par2Error::MissingMainPacket)?,
            file_descriptions,
            slice_checksums,
            recovery_slices,
            creators,
            warnings,
        })
    }

    pub fn validate(self) -> Result<Par2ValidatedSet, Par2Error> {
        if self.main.computed_md5 != self.main.expected_md5 {
            return Err(Par2Error::MainPacketIntegrityFailure);
        }

        let mut warnings = self.warnings;

        let valid_file_descriptions = validate_and_filter(
            Par2WarningDataType::FileDescription,
            self.file_descriptions,
            self.recovery_set_id,
            &mut warnings,
        );

        let valid_slice_checksums = validate_and_filter(
            Par2WarningDataType::SliceChecksum,
            self.slice_checksums,
            self.recovery_set_id,
            &mut warnings,
        );

        let had_recovery_slices = !self.recovery_slices.is_empty();
        let valid_recovery_slices = validate_and_filter(
            Par2WarningDataType::RecoverySlice,
            self.recovery_slices,
            self.recovery_set_id,
            &mut warnings,
        );

        let valid_creators = validate_and_filter(
            Par2WarningDataType::Creator,
            self.creators,
            self.recovery_set_id,
            &mut warnings,
        );

        if valid_recovery_slices.is_empty() && had_recovery_slices {
            warnings.push(Par2Warning::AllRecoverySlicesCorrupt);
        }

        if valid_slice_checksums.is_empty() {
            return Err(Par2Error::AllSliceChecksumsCorrupt);
        }

        if valid_file_descriptions.is_empty() {
            return Err(Par2Error::AllFileDescriptionsCorrupt);
        }

        Ok(Par2ValidatedSet {
            recovery_set_id: self.recovery_set_id,
            main: self.main.data,
            file_descriptions: valid_file_descriptions,
            slice_checksums: valid_slice_checksums,
            recovery_slices: valid_recovery_slices,
            creators: valid_creators,
            warnings,
        })
    }
}

fn validate_and_filter<T>(
    data_type: Par2WarningDataType,
    data: Vec<Parsed<T>>,
    recovery_set_id: Par2RecoverySetId,
    warnings: &mut Vec<Par2Warning>,
) -> Vec<T> {
    let mut valid_data = Vec::new();

    for parsed_data in data {
        if parsed_data.recovery_set_id != recovery_set_id {
            warnings.push(Par2Warning::UnexpectedRecoverySetId(
                data_type,
                recovery_set_id,
                parsed_data.recovery_set_id,
            ));
            continue;
        }

        if parsed_data.computed_md5 != parsed_data.expected_md5 {
            warnings.push(Par2Warning::IntegrityFailure(
                data_type,
                parsed_data.computed_md5,
                parsed_data.expected_md5,
            ));
            continue;
        }
        valid_data.push(parsed_data.data);
    }

    valid_data
}
