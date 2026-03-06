use crate::error::Par2Error;
use std::path::{Path, PathBuf};

pub fn locate_files(base_file: &Path) -> Result<Vec<PathBuf>, Par2Error> {
    let mut files = vec![base_file.to_path_buf()];

    let parent_path = base_file
        .parent()
        .ok_or(Par2Error::FilePathError("Missing parent directory".into()))?;

    let base_file_stem = base_file
        .file_stem()
        .ok_or(Par2Error::FilePathError("Missing file stem".into()))?
        .to_str()
        .ok_or(Par2Error::FilePathError(
            "Unable to convert file stem to string".into(),
        ))?;

    let pattern_path = Path::join(parent_path, format!("{}.vol*.par2", base_file_stem));
    let pattern = pattern_path.to_str().ok_or(Par2Error::FilePathError(
        "Unable to convert pattern path to string".into(),
    ))?;

    let additional_files = glob::glob(pattern).map_err(|e| {
        Par2Error::FilePathError(format!("Failed to glob pattern '{}': {}", pattern, e))
    })?;

    for entry in additional_files {
        let entry_path = entry
            .map_err(|e| Par2Error::FilePathError(format!("{}", e)))?
            .to_path_buf();

        files.push(entry_path);
    }

    Ok(files)
}
