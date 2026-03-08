use crate::error::Par2Error;
use std::path::{Path, PathBuf};

pub fn locate_files(base: &Path) -> Result<Vec<PathBuf>, Par2Error> {
    if !base.is_file() {
        return Err(Par2Error::FilePathError(format!(
            "\"{}\" is not a valid file",
            base.display()
        )));
    }

    let mut files = vec![base.to_path_buf()];

    let parent_path = base
        .parent()
        .ok_or(Par2Error::FilePathError("missing parent directory".into()))?;

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
