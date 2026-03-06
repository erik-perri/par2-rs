use crate::error::{Par2Error, Par2Warning};
use crate::packet::{
    Par2CreatorData, Par2FileDescriptionData, Par2MainData, Par2Md5Hash, Par2Packet,
    Par2PacketBody, Par2RecoverySliceData, Par2SliceChecksumData,
};

#[derive(Debug)]
struct Parsed<T> {
    expected_md5: Par2Md5Hash,
    computed_md5: Par2Md5Hash,
    data: T,
}

#[derive(Debug)]
pub struct Par2Set {
    recovery_set_id: [u8; 16],
    main: Parsed<Par2MainData>,
    file_descriptions: Vec<Parsed<Par2FileDescriptionData>>,
    slice_checksums: Vec<Parsed<Par2SliceChecksumData>>,
    recovery_slices: Vec<Parsed<Par2RecoverySliceData>>,
    creators: Vec<Parsed<Par2CreatorData>>,
}

pub fn combine_set(packets: Vec<Par2Packet>) -> Result<(Par2Set, Vec<Par2Warning>), Par2Error> {
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
                        return Err(Par2Error::DuplicateMainPacket);
                    }

                    continue;
                }

                recovery_set_id = Some(packet.header.recovery_set_id);

                main = Some(Parsed {
                    expected_md5: packet.header.expected_md5,
                    computed_md5,
                    data,
                });
            }
            Par2PacketBody::FileDesc(data) => file_descriptions.push(Parsed {
                expected_md5: packet.header.expected_md5,
                computed_md5,
                data,
            }),
            Par2PacketBody::SliceChecksum(data) => slice_checksums.push(Parsed {
                expected_md5: packet.header.expected_md5,
                computed_md5,
                data,
            }),
            Par2PacketBody::RecoverySlice(data) => recovery_slices.push(Parsed {
                expected_md5: packet.header.expected_md5,
                computed_md5,
                data,
            }),
            Par2PacketBody::Creator(data) => creators.push(Parsed {
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

    Ok((
        Par2Set {
            recovery_set_id: recovery_set_id.ok_or(Par2Error::MissingRecoverySetId)?,
            main: main.ok_or(Par2Error::MissingMainPacket)?,
            file_descriptions,
            slice_checksums,
            recovery_slices,
            creators,
        },
        warnings,
    ))
}
