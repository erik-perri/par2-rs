use crate::error::{Par2Error, Par2Warning, Par2WarningDataType};
use crate::packet::{
    Par2CreatorData, Par2FileDescriptionData, Par2FileId, Par2MainData, Par2Md5Hash, Par2Packet,
    Par2PacketBody, Par2RecoverySetId, Par2RecoverySliceData, Par2SliceChecksumData,
};
use std::collections::HashMap;
use std::collections::hash_map::Entry;

#[derive(Debug)]
pub(crate) struct Parsed<T> {
    pub(crate) computed_md5: Par2Md5Hash,
    pub(crate) data: T,
    pub(crate) expected_md5: Par2Md5Hash,
    pub(crate) recovery_set_id: Par2RecoverySetId,
}

#[derive(Debug)]
pub(crate) struct Par2ParsedSet {
    recovery_set_id: Par2RecoverySetId,
    main: Parsed<Par2MainData>,
    file_descriptions: Vec<Parsed<Par2FileDescriptionData>>,
    slice_checksums: Vec<Parsed<Par2SliceChecksumData>>,
    recovery_slices: Vec<Parsed<Par2RecoverySliceData>>,
    creators: Vec<Parsed<Par2CreatorData>>,
    warnings: Vec<Par2Warning>,
}

#[derive(Debug)]
pub(crate) struct Par2Set {
    pub(crate) recovery_set_id: Par2RecoverySetId,
    pub(crate) main: Par2MainData,
    pub(crate) file_descriptions: HashMap<Par2FileId, Par2FileDescriptionData>,
    pub(crate) slice_checksums: HashMap<Par2FileId, Par2SliceChecksumData>,
    pub(crate) recovery_slices: Vec<Par2RecoverySliceData>,
    pub(crate) creators: Vec<Par2CreatorData>,
    pub(crate) warnings: Vec<Par2Warning>,
}

impl Par2ParsedSet {
    pub fn from_packets(packets: Vec<Par2Packet>) -> Result<Par2ParsedSet, Par2Error> {
        let mut recovery_set_id = None;
        let mut main: Option<Parsed<Par2MainData>> = None;
        let mut file_descriptions = Vec::new();
        let mut slice_checksums = Vec::new();
        let mut recovery_slices = Vec::new();
        let mut creators = Vec::new();
        let mut warnings = Vec::new();

        for packet in packets {
            match packet.body {
                Par2PacketBody::Main(data) => {
                    if let Some(main) = main.as_ref() {
                        if main.expected_md5 != packet.header.expected_md5
                            || main.computed_md5 != packet.header.computed_md5
                            || main.recovery_set_id != packet.header.recovery_set_id
                        {
                            return Err(Par2Error::MainPacketConflict);
                        }

                        continue;
                    }

                    recovery_set_id = Some(packet.header.recovery_set_id);

                    main = Some(Parsed {
                        recovery_set_id: packet.header.recovery_set_id,
                        expected_md5: packet.header.expected_md5,
                        computed_md5: packet.header.computed_md5,
                        data,
                    });
                }
                Par2PacketBody::FileDesc(data) => file_descriptions.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5: packet.header.computed_md5,
                    data,
                }),
                Par2PacketBody::SliceChecksum(data) => slice_checksums.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5: packet.header.computed_md5,
                    data,
                }),
                Par2PacketBody::RecoverySlice(data) => recovery_slices.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5: packet.header.computed_md5,
                    data,
                }),
                Par2PacketBody::Creator(data) => creators.push(Parsed {
                    recovery_set_id: packet.header.recovery_set_id,
                    expected_md5: packet.header.expected_md5,
                    computed_md5: packet.header.computed_md5,
                    data,
                }),
                Par2PacketBody::Unknown(packet_type) => {
                    warnings.push(Par2Warning::UnknownPacketType(packet_type));
                }
            }
        }

        let main = main.ok_or(Par2Error::MissingMainPacket)?;
        let recovery_set_id = recovery_set_id.ok_or(Par2Error::MissingMainPacket)?;

        if creators.is_empty() {
            warnings.push(Par2Warning::MissingCreator);
        }

        if file_descriptions.is_empty() {
            return Err(Par2Error::MissingFileDescriptions);
        }

        if slice_checksums.is_empty() {
            return Err(Par2Error::MissingSliceChecksums);
        }

        Ok(Par2ParsedSet {
            recovery_set_id,
            main,
            file_descriptions,
            slice_checksums,
            recovery_slices,
            creators,
            warnings,
        })
    }

    pub fn validate(self) -> Result<Par2Set, Par2Error> {
        if self.main.computed_md5 != self.main.expected_md5
            || self.main.recovery_set_id != self.main.data.computed_recovery_set_id
        {
            return Err(Par2Error::MainPacketIntegrityFailure);
        }

        if self.main.data.slice_size == 0 {
            return Err(Par2Error::InvalidMainPacket(
                "slice size is zero".to_string(),
            ));
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

        let slice_checksums = dedup_by_file_id(
            valid_slice_checksums,
            &mut warnings,
            |sc| sc.file_id,
            Par2Warning::UnexpectedSliceData,
        );

        let file_descriptions = dedup_by_file_id(
            valid_file_descriptions,
            &mut warnings,
            |fd| fd.file_id,
            Par2Warning::UnexpectedFileDescription,
        );

        Ok(Par2Set {
            recovery_set_id: self.recovery_set_id,
            main: self.main.data,
            file_descriptions,
            slice_checksums,
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

fn dedup_by_file_id<T>(
    items: Vec<T>,
    warnings: &mut Vec<Par2Warning>,
    file_id_extractor: impl Fn(&T) -> Par2FileId,
    warning_builder: impl Fn(Par2FileId) -> Par2Warning,
) -> HashMap<Par2FileId, T>
where
    T: PartialEq,
{
    let mut map: HashMap<Par2FileId, T> = HashMap::new();

    for item in items {
        let file_id = file_id_extractor(&item);

        match map.entry(file_id) {
            Entry::Occupied(existing) => {
                if existing.get() != &item {
                    warnings.push(warning_builder(file_id));
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(item);
            }
        };
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    mod par2_parsed_set {
        use super::*;
        use crate::packet::Par2PacketHeader;

        fn make_packet(
            body: Par2PacketBody,
            packet_type: &[u8; 16],
            recovery_set_id: Par2RecoverySetId,
            md5: Par2Md5Hash,
        ) -> Par2Packet {
            Par2Packet {
                header: Par2PacketHeader {
                    packet_length: 64,
                    expected_md5: Par2Md5Hash(md5.0),
                    computed_md5: Par2Md5Hash(md5.0),
                    recovery_set_id,
                    packet_type: *packet_type,
                },
                body,
            }
        }

        mod from_packets {
            use super::*;
            use crate::packet::{
                PAR2_PACKET_MAGIC_CREATOR, PAR2_PACKET_MAGIC_FILE_DESC, PAR2_PACKET_MAGIC_MAIN,
                PAR2_PACKET_MAGIC_SLICE_CHECKSUM, Par2FileId, Par2SliceChecksumEntry,
            };

            fn make_minimal_main(recovery_set_id: Par2RecoverySetId) -> Par2Packet {
                make_packet(
                    Par2PacketBody::Main(Par2MainData {
                        computed_recovery_set_id: recovery_set_id,
                        non_recovery_file_ids: vec![],
                        recovery_file_ids: vec![],
                        slice_size: 1024,
                    }),
                    PAR2_PACKET_MAGIC_MAIN,
                    recovery_set_id,
                    Par2Md5Hash([0x10; 16]),
                )
            }

            fn make_minimal_file_desc(recovery_set_id: Par2RecoverySetId) -> Par2Packet {
                make_packet(
                    Par2PacketBody::FileDesc(Par2FileDescriptionData {
                        file_id: Par2FileId([0x00; 16]),
                        file_md5: Par2Md5Hash([0xBB; 16]),
                        file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                        file_length: 0,
                        file_name: "test.txt".to_string(),
                    }),
                    PAR2_PACKET_MAGIC_FILE_DESC,
                    recovery_set_id,
                    Par2Md5Hash([0x20; 16]),
                )
            }

            fn make_minimal_slice_checksum(recovery_set_id: Par2RecoverySetId) -> Par2Packet {
                make_packet(
                    Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
                        file_id: Par2FileId([0x00; 16]),
                        entries: vec![Par2SliceChecksumEntry {
                            md5: Par2Md5Hash([0xBB; 16]),
                            crc32: 0xDEADBEEF,
                        }],
                    }),
                    PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
                    recovery_set_id,
                    Par2Md5Hash([0x30; 16]),
                )
            }

            fn make_minimal_creator(recovery_set_id: Par2RecoverySetId) -> Par2Packet {
                make_packet(
                    Par2PacketBody::Creator(Par2CreatorData {
                        name: "test-creator".to_string(),
                    }),
                    PAR2_PACKET_MAGIC_CREATOR,
                    recovery_set_id,
                    Par2Md5Hash([0x40; 16]),
                )
            }

            fn make_minimal_valid_set() -> Vec<Par2Packet> {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                vec![
                    make_minimal_main(recovery_set_id),
                    make_minimal_file_desc(recovery_set_id),
                    make_minimal_slice_checksum(recovery_set_id),
                    make_minimal_creator(recovery_set_id),
                ]
            }

            #[test]
            fn accepts_valid_set() {
                let packets = make_minimal_valid_set();

                let result = Par2ParsedSet::from_packets(packets);

                assert!(result.is_ok());
            }

            #[test]
            fn missing_packets() {
                let packets = vec![];

                let result = Par2ParsedSet::from_packets(packets);

                assert!(matches!(result, Err(Par2Error::MissingMainPacket)));
            }

            #[test]
            fn missing_main_packet() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_minimal_file_desc(recovery_set_id),
                    make_minimal_slice_checksum(recovery_set_id),
                ];

                let result = Par2ParsedSet::from_packets(packets);

                assert!(matches!(result, Err(Par2Error::MissingMainPacket)));
            }

            #[test]
            fn missing_file_descriptions() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_minimal_main(recovery_set_id),
                    make_minimal_slice_checksum(recovery_set_id),
                ];

                let result = Par2ParsedSet::from_packets(packets);

                assert!(matches!(result, Err(Par2Error::MissingFileDescriptions)));
            }

            #[test]
            fn missing_slice_checksums() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_minimal_main(recovery_set_id),
                    make_minimal_file_desc(recovery_set_id),
                ];

                let result = Par2ParsedSet::from_packets(packets);

                assert!(matches!(result, Err(Par2Error::MissingSliceChecksums)));
            }

            #[test]
            fn unknown_packet_type_produces_warning() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let mut packets = make_minimal_valid_set();
                packets.push(make_packet(
                    Par2PacketBody::Unknown([0xFF; 16]),
                    &[0xFF; 16],
                    recovery_set_id,
                    Par2Md5Hash([0x50; 16]),
                ));

                let set = Par2ParsedSet::from_packets(packets).unwrap();

                assert!(
                    set.warnings
                        .iter()
                        .any(|w| matches!(w, Par2Warning::UnknownPacketType(..)))
                );
            }

            #[test]
            fn missing_creator_produces_warning() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_minimal_main(recovery_set_id),
                    make_minimal_file_desc(recovery_set_id),
                    make_minimal_slice_checksum(recovery_set_id),
                ];

                let set = Par2ParsedSet::from_packets(packets).unwrap();

                assert!(
                    set.warnings
                        .iter()
                        .any(|w| matches!(w, Par2Warning::MissingCreator))
                );
            }

            #[test]
            fn duplicate_main_packet_dedupes() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let mut packets = make_minimal_valid_set();
                packets.push(make_minimal_main(recovery_set_id));

                let set = Par2ParsedSet::from_packets(packets).unwrap();

                assert_eq!(set.warnings.len(), 0,);
            }

            #[test]
            fn conflicting_main_packet_recovery_id_fails() {
                let other_recovery_set_id = Par2RecoverySetId([0x02; 16]);

                let mut packets = make_minimal_valid_set();
                packets.push(make_minimal_main(other_recovery_set_id));

                let set = Par2ParsedSet::from_packets(packets);

                assert!(set.is_err());
                assert!(matches!(set, Err(Par2Error::MainPacketConflict)));
            }

            #[test]
            fn conflicting_main_packet_expected_md5_fails() {
                let mut other_main_packet = make_minimal_main(Par2RecoverySetId([0x01; 16]));
                other_main_packet.header.expected_md5 = Par2Md5Hash([0xDD; 16]);

                let mut packets = make_minimal_valid_set();
                packets.push(other_main_packet);

                let set = Par2ParsedSet::from_packets(packets);

                assert!(set.is_err());
                assert!(matches!(set, Err(Par2Error::MainPacketConflict)));
            }

            #[test]
            fn conflicting_main_packet_computed_md5_fails() {
                let mut other_main_packet = make_minimal_main(Par2RecoverySetId([0x01; 16]));
                other_main_packet.header.computed_md5 = Par2Md5Hash([0xDD; 16]);

                let mut packets = make_minimal_valid_set();
                packets.push(other_main_packet);

                let set = Par2ParsedSet::from_packets(packets);

                assert!(set.is_err());
                assert!(matches!(set, Err(Par2Error::MainPacketConflict)));
            }
        }

        mod validate {
            use super::*;
            use crate::packet::{
                PAR2_PACKET_MAGIC_CREATOR, PAR2_PACKET_MAGIC_FILE_DESC, PAR2_PACKET_MAGIC_MAIN,
                PAR2_PACKET_MAGIC_RECOVERY_SLICE, PAR2_PACKET_MAGIC_SLICE_CHECKSUM, Par2FileId,
                Par2PacketHeader, Par2SliceChecksumEntry,
            };

            fn valid_parsed_set() -> Par2ParsedSet {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_packet(
                        Par2PacketBody::Main(Par2MainData {
                            computed_recovery_set_id: recovery_set_id,
                            non_recovery_file_ids: vec![],
                            recovery_file_ids: vec![],
                            slice_size: 1024,
                        }),
                        PAR2_PACKET_MAGIC_MAIN,
                        recovery_set_id,
                        Par2Md5Hash([0x10; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::FileDesc(Par2FileDescriptionData {
                            file_id: Par2FileId([0x00; 16]),
                            file_md5: Par2Md5Hash([0xBB; 16]),
                            file_first_16kb_md5: Par2Md5Hash([0xCC; 16]),
                            file_length: 0,
                            file_name: "test.txt".to_string(),
                        }),
                        PAR2_PACKET_MAGIC_FILE_DESC,
                        recovery_set_id,
                        Par2Md5Hash([0x20; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
                            file_id: Par2FileId([0x00; 16]),
                            entries: vec![Par2SliceChecksumEntry {
                                md5: Par2Md5Hash([0xDD; 16]),
                                crc32: 0xDEADBEEF,
                            }],
                        }),
                        PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
                        recovery_set_id,
                        Par2Md5Hash([0x30; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::Creator(Par2CreatorData {
                            name: "test-creator".to_string(),
                        }),
                        PAR2_PACKET_MAGIC_CREATOR,
                        recovery_set_id,
                        Par2Md5Hash([0x40; 16]),
                    ),
                ];
                Par2ParsedSet::from_packets(packets).unwrap()
            }

            #[test]
            fn clean_set_validates() {
                let set = valid_parsed_set();

                let result = set.validate();

                assert!(result.is_ok());
            }

            #[test]
            fn main_packet_md5_mismatch() {
                let mut set = valid_parsed_set();

                // Corrupt the main packet's computed MD5 so it no longer matches expected
                set.main.computed_md5 = Par2Md5Hash([0xFF; 16]);

                let result = set.validate();

                assert!(matches!(result, Err(Par2Error::MainPacketIntegrityFailure)));
            }

            #[test]
            fn all_file_descriptions_corrupt() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_packet(
                        Par2PacketBody::Main(Par2MainData {
                            computed_recovery_set_id: recovery_set_id,
                            non_recovery_file_ids: vec![],
                            recovery_file_ids: vec![],
                            slice_size: 1024,
                        }),
                        PAR2_PACKET_MAGIC_MAIN,
                        recovery_set_id,
                        Par2Md5Hash([0x10; 16]),
                    ),
                    // File description with mismatched MD5 (will be filtered out)
                    Par2Packet {
                        header: Par2PacketHeader {
                            packet_length: 64,
                            expected_md5: Par2Md5Hash([0x20; 16]),
                            computed_md5: Par2Md5Hash([0xFF; 16]),
                            recovery_set_id,
                            packet_type: *PAR2_PACKET_MAGIC_FILE_DESC,
                        },
                        body: Par2PacketBody::FileDesc(Par2FileDescriptionData {
                            file_id: Par2FileId([0x00; 16]),
                            file_md5: Par2Md5Hash([0xEE; 16]),
                            file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                            file_length: 0,
                            file_name: "test.txt".to_string(),
                        }),
                    },
                    make_packet(
                        Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
                            file_id: Par2FileId([0x00; 16]),
                            entries: vec![Par2SliceChecksumEntry {
                                md5: Par2Md5Hash([0xCC; 16]),
                                crc32: 0xDEADBEEF,
                            }],
                        }),
                        PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
                        recovery_set_id,
                        Par2Md5Hash([0x30; 16]),
                    ),
                ];
                let set = Par2ParsedSet::from_packets(packets).unwrap();

                let result = set.validate();

                assert!(matches!(result, Err(Par2Error::AllFileDescriptionsCorrupt)));
            }

            #[test]
            fn all_slice_checksums_corrupt() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_packet(
                        Par2PacketBody::Main(Par2MainData {
                            computed_recovery_set_id: recovery_set_id,
                            non_recovery_file_ids: vec![],
                            recovery_file_ids: vec![],
                            slice_size: 1024,
                        }),
                        PAR2_PACKET_MAGIC_MAIN,
                        recovery_set_id,
                        Par2Md5Hash([0x10; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::FileDesc(Par2FileDescriptionData {
                            file_id: Par2FileId([0x00; 16]),
                            file_md5: Par2Md5Hash([0xAA; 16]),
                            file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                            file_length: 0,
                            file_name: "test.txt".to_string(),
                        }),
                        PAR2_PACKET_MAGIC_FILE_DESC,
                        recovery_set_id,
                        Par2Md5Hash([0x20; 16]),
                    ),
                    // Slice checksum with mismatched MD5 (will be filtered out)
                    Par2Packet {
                        header: Par2PacketHeader {
                            packet_length: 64,
                            expected_md5: Par2Md5Hash([0x30; 16]),
                            computed_md5: Par2Md5Hash([0xFF; 16]),
                            recovery_set_id,
                            packet_type: *PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
                        },
                        body: Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
                            file_id: Par2FileId([0x00; 16]),
                            entries: vec![Par2SliceChecksumEntry {
                                md5: Par2Md5Hash([0xCC; 16]),
                                crc32: 0xDEADBEEF,
                            }],
                        }),
                    },
                ];
                let set = Par2ParsedSet::from_packets(packets).unwrap();

                let result = set.validate();

                assert!(matches!(result, Err(Par2Error::AllSliceChecksumsCorrupt)));
            }

            #[test]
            fn all_recovery_slices_corrupt_produces_warning() {
                let recovery_set_id = Par2RecoverySetId([0x01; 16]);
                let packets = vec![
                    make_packet(
                        Par2PacketBody::Main(Par2MainData {
                            computed_recovery_set_id: recovery_set_id,
                            non_recovery_file_ids: vec![],
                            recovery_file_ids: vec![],
                            slice_size: 1024,
                        }),
                        PAR2_PACKET_MAGIC_MAIN,
                        recovery_set_id,
                        Par2Md5Hash([0x10; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::FileDesc(Par2FileDescriptionData {
                            file_id: Par2FileId([0x00; 16]),
                            file_md5: Par2Md5Hash([0xFF; 16]),
                            file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                            file_length: 0,
                            file_name: "test.txt".to_string(),
                        }),
                        PAR2_PACKET_MAGIC_FILE_DESC,
                        recovery_set_id,
                        Par2Md5Hash([0x20; 16]),
                    ),
                    make_packet(
                        Par2PacketBody::SliceChecksum(Par2SliceChecksumData {
                            file_id: Par2FileId([0x00; 16]),
                            entries: vec![Par2SliceChecksumEntry {
                                md5: Par2Md5Hash([0xEE; 16]),
                                crc32: 0xDEADBEEF,
                            }],
                        }),
                        PAR2_PACKET_MAGIC_SLICE_CHECKSUM,
                        recovery_set_id,
                        Par2Md5Hash([0x30; 16]),
                    ),
                    // Recovery slice with mismatched MD5 (will be filtered out)
                    Par2Packet {
                        header: Par2PacketHeader {
                            packet_length: 64,
                            expected_md5: Par2Md5Hash([0x50; 16]),
                            computed_md5: Par2Md5Hash([0xFF; 16]),
                            recovery_set_id,
                            packet_type: *PAR2_PACKET_MAGIC_RECOVERY_SLICE,
                        },
                        body: Par2PacketBody::RecoverySlice(Par2RecoverySliceData {
                            exponent: 0,
                            recovery_data: vec![0x00; 1024],
                        }),
                    },
                ];
                let set = Par2ParsedSet::from_packets(packets).unwrap();

                let validated = set.validate().unwrap();

                assert!(
                    validated
                        .warnings
                        .iter()
                        .any(|w| matches!(w, Par2Warning::AllRecoverySlicesCorrupt))
                );
            }
        }
    }

    mod validate_and_filter {
        use super::*;
        use crate::packet::Par2FileId;

        #[test]
        fn filters_unknown_recovery_set_ids() {
            let recovery_set_id = Par2RecoverySetId([0x01; 16]);
            let data: Vec<Parsed<Par2FileDescriptionData>> = vec![
                Parsed {
                    recovery_set_id,
                    computed_md5: Par2Md5Hash([0xBB; 16]),
                    expected_md5: Par2Md5Hash([0xBB; 16]),
                    data: Par2FileDescriptionData {
                        file_id: Par2FileId([0xDD; 16]),
                        file_md5: Par2Md5Hash([0xAA; 16]),
                        file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                        file_length: 0,
                        file_name: "test-a.txt".to_string(),
                    },
                },
                Parsed {
                    recovery_set_id: Par2RecoverySetId([0x02; 16]),
                    computed_md5: Par2Md5Hash([0xAA; 16]),
                    expected_md5: Par2Md5Hash([0xAA; 16]),
                    data: Par2FileDescriptionData {
                        file_id: Par2FileId([0x00; 16]),
                        file_md5: Par2Md5Hash([0xAA; 16]),
                        file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                        file_length: 0,
                        file_name: "test-b.txt".to_string(),
                    },
                },
            ];

            let mut warnings = Vec::new();
            let filtered_data = validate_and_filter(
                Par2WarningDataType::FileDescription,
                data,
                recovery_set_id,
                &mut warnings,
            );

            assert_eq!(filtered_data.len(), 1);
            assert_eq!(filtered_data[0].file_name, "test-a.txt".to_string());

            assert_eq!(warnings.len(), 1);
            assert!(matches!(
                warnings[0],
                Par2Warning::UnexpectedRecoverySetId(..)
            ));
        }

        #[test]
        fn filters_mismatched_md5() {
            let recovery_set_id = Par2RecoverySetId([0x01; 16]);
            let data: Vec<Parsed<Par2FileDescriptionData>> = vec![Parsed {
                recovery_set_id,
                computed_md5: Par2Md5Hash([0xBB; 16]),
                expected_md5: Par2Md5Hash([0xAA; 16]),
                data: Par2FileDescriptionData {
                    file_id: Par2FileId([0x00; 16]),
                    file_md5: Par2Md5Hash([0xAA; 16]),
                    file_first_16kb_md5: Par2Md5Hash([0xBB; 16]),
                    file_length: 0,
                    file_name: "test-a.txt".to_string(),
                },
            }];

            let mut warnings = Vec::new();
            let filtered_data = validate_and_filter(
                Par2WarningDataType::FileDescription,
                data,
                recovery_set_id,
                &mut warnings,
            );

            assert_eq!(filtered_data.len(), 0);

            assert_eq!(warnings.len(), 1);
            assert!(matches!(warnings[0], Par2Warning::IntegrityFailure(..)));
        }
    }
}
