use crate::error::Par2Error;
use crate::packet::{Par2FileId, Par2Md5Hash, Par2SliceChecksumEntry};
use byteorder::{LittleEndian, WriteBytesExt};
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Par2ComputedFileData {
    pub(crate) computed_slice_checksums: Vec<Par2SliceChecksumEntry>,
    pub(crate) file_id: Par2FileId,
    pub(crate) file_length: u64,
    pub(crate) file_md5: Par2Md5Hash,
    pub(crate) file_name: String,
    pub(crate) file_path: PathBuf,
    pub(crate) first_16kb_md5: Par2Md5Hash,
}

pub(crate) fn compute_file_data(
    file_path: &Path,
    slice_size: u64,
) -> Result<Par2ComputedFileData, Par2Error> {
    let file_metadata = file_path.metadata()?;

    let file_name = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Par2Error::FilePathError("file path is missing or not valid utf-8".into())
        })?;

    let file_length = file_metadata.len();
    let file = File::open(file_path)?;

    let first_16kb_size = (16 * 1024).min(file_length);

    let mut reader = BufReader::new(file);
    let mut slice_buffer = vec![0u8; slice_size as usize];
    let mut first_16kb_buffer = vec![0u8; first_16kb_size as usize];

    reader.read_exact(&mut first_16kb_buffer)?;

    reader.seek(SeekFrom::Start(0))?;

    let first_16kb_md5 = Par2Md5Hash(Md5::digest(&first_16kb_buffer).into());

    let mut file_md5_hasher = Md5::new();
    let mut computed_slice_checksums = Vec::new();

    loop {
        slice_buffer.clear();

        let read_length = (&mut reader)
            .take(slice_size)
            .read_to_end(&mut slice_buffer)?;

        if read_length == 0 {
            break;
        }

        file_md5_hasher.update(&slice_buffer[..read_length]);

        let mut slice_md5_hasher = Md5::new();
        let mut slice_crc32_hasher = crc32fast::Hasher::new();

        let padding_length = (slice_size - (read_length as u64)) % slice_size;
        let padding_buffer = vec![0; padding_length as usize];

        slice_md5_hasher.update(&slice_buffer[..read_length]);
        slice_md5_hasher.update(&padding_buffer);

        slice_crc32_hasher.update(&slice_buffer[..read_length]);
        slice_crc32_hasher.update(&padding_buffer);

        let slice_md5 = Par2Md5Hash(slice_md5_hasher.finalize().into());
        let slice_crc32 = slice_crc32_hasher.finalize();

        computed_slice_checksums.push(Par2SliceChecksumEntry {
            md5: slice_md5,
            crc32: slice_crc32,
        })
    }

    let file_md5 = Par2Md5Hash(file_md5_hasher.finalize().into());
    let file_id = compute_file_id(file_name, file_length, &first_16kb_md5);

    Ok(Par2ComputedFileData {
        computed_slice_checksums,
        file_id,
        file_length,
        file_md5,
        file_name: file_name.to_string(),
        file_path: file_path.to_path_buf(),
        first_16kb_md5,
    })
}

pub(crate) fn compute_file_id(
    file_name: &str,
    file_length: u64,
    first_16kb_md5: &Par2Md5Hash,
) -> Par2FileId {
    let mut buffer = Vec::new();

    buffer.extend_from_slice(first_16kb_md5.as_ref());
    buffer.write_u64::<LittleEndian>(file_length).unwrap();
    buffer.extend_from_slice(file_name.as_bytes());

    let computed_file_id = Par2Md5Hash(Md5::digest(&buffer).into());

    Par2FileId::from(computed_file_id)
}

pub fn locate_files(base: &Path) -> Result<Vec<PathBuf>, Par2Error> {
    if !base.is_file() {
        return Err(Par2Error::FilePathError(format!(
            "\"{}\" is not a valid file",
            base.display()
        )));
    }

    let mut files = vec![base.to_path_buf()];

    let parent_path = base.parent().unwrap_or(Path::new("."));

    let base_file_stem = base
        .file_stem()
        .ok_or(Par2Error::FilePathError("missing file stem".into()))?
        .to_str()
        .ok_or(Par2Error::FilePathError(
            "file stem is not valid utf-8".into(),
        ))?;

    let escaped_stem = glob::Pattern::escape(base_file_stem);
    let pattern_path = Path::join(parent_path, format!("{}.vol*.par2", escaped_stem));
    let pattern = pattern_path.to_str().ok_or(Par2Error::FilePathError(
        "pattern path is not valid utf-8".into(),
    ))?;

    let options = glob::MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    let additional_files = glob::glob_with(pattern, options).map_err(|e| {
        Par2Error::FilePathError(format!("invalid glob pattern '{}': {}", pattern, e))
    })?;

    for entry in additional_files {
        let entry_path = entry
            .map_err(|e| Par2Error::FilePathError(format!("{}", e)))?
            .to_path_buf();

        files.push(entry_path);
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn with_volume_files() {
        let temp_dir = TempDir::new().unwrap();

        File::create(temp_dir.path().join("backup.par2")).unwrap();
        File::create(temp_dir.path().join("backup.vol000+01.par2")).unwrap();
        File::create(temp_dir.path().join("backup.vol001+02.par2")).unwrap();

        File::create(temp_dir.path().join("other.vol000+01.par2")).unwrap();

        let result = locate_files(&temp_dir.path().join("backup.par2")).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0], temp_dir.path().join("backup.par2"));
        assert_eq!(result[1], temp_dir.path().join("backup.vol000+01.par2"));
        assert_eq!(result[2], temp_dir.path().join("backup.vol001+02.par2"));
    }

    #[test]
    fn no_volume_files() {
        let temp_dir = TempDir::new().unwrap();

        File::create(temp_dir.path().join("backup.par2")).unwrap();
        File::create(temp_dir.path().join("other.par2")).unwrap();

        let result = locate_files(&temp_dir.path().join("backup.par2")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], temp_dir.path().join("backup.par2"));
    }

    #[test]
    fn excludes_nonexistent_base_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("why_did_you_break_tests.par2");

        let result = locate_files(&nonexistent);

        assert!(result.is_err());
    }

    #[test]
    fn with_special_glob_characters_in_filename() {
        let temp_dir = TempDir::new().unwrap();

        // When unescaped, the glob turns `[2024]` into `0|2|4` and no longer matches.
        File::create(temp_dir.path().join("backup[2024].par2")).unwrap();
        File::create(temp_dir.path().join("backup[2024].vol000+01.par2")).unwrap();

        let result = locate_files(&temp_dir.path().join("backup[2024].par2")).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], temp_dir.path().join("backup[2024].par2"));
        assert_eq!(
            result[1],
            temp_dir.path().join("backup[2024].vol000+01.par2")
        );
    }

    #[test]
    fn with_invalid_glob_characters_in_filename() {
        let temp_dir = TempDir::new().unwrap();

        // When unescaped, the incomplete brackets `[` would produce a glob failure.
        File::create(temp_dir.path().join("backup[2024.par2")).unwrap();
        File::create(temp_dir.path().join("backup[2024.vol000+01.par2")).unwrap();

        let result = locate_files(&temp_dir.path().join("backup[2024.par2")).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn with_case_differences_in_filenames() {
        let temp_dir = TempDir::new().unwrap();

        File::create(temp_dir.path().join("backup.par2")).unwrap();
        File::create(temp_dir.path().join("backup.vol000+01.PAR2")).unwrap();
        File::create(temp_dir.path().join("backup.vol000+02.Par2")).unwrap();

        let result = locate_files(&temp_dir.path().join("backup.par2")).unwrap();

        assert_eq!(result.len(), 3);
    }
}
