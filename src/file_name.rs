use crate::error::Par2Error;
use std::ops::{Div, Mul};
use std::path::{Component, Path, PathBuf};

pub(crate) fn get_sanitized_file_path(
    base_path: &Path,
    file_name: &str,
) -> Result<PathBuf, Par2Error> {
    let components = Path::new(&file_name).components();
    let mut parts = Vec::new();

    for component in components {
        match component {
            Component::Normal(seg) => parts.push(seg),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Par2Error::FilePathError(format!(
                    "file \"{}\" contains unsupported path",
                    file_name
                )));
            }
        }
    }

    if parts.is_empty() {
        return Err(Par2Error::FilePathError(format!(
            "file \"{}\" resolved to empty path",
            file_name
        )));
    }

    let safe_path: PathBuf = parts.into_iter().collect();

    Ok(base_path.join(safe_path))
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Par2FileSpec {
    pub(crate) file_name: String,
    pub(crate) starting_exponent: u16,
    pub(crate) block_count: u16,
}

pub(crate) fn plan_recovery_files(
    base_file_name: &Path,
    recovery_block_count: u16,
) -> Result<Vec<Par2FileSpec>, Par2Error> {
    let file_stem = base_file_name
        .file_stem()
        .ok_or(Par2Error::FilePathError("missing file stem".into()))?
        .to_str()
        .ok_or(Par2Error::FilePathError(
            "file stem is not valid utf-8".into(),
        ))?;

    let mut remaining = recovery_block_count;
    let mut power = 1;
    let mut current_exponent = 0;

    let mut files = Vec::new();

    files.push(Par2FileSpec {
        file_name: format!("{}.par2", file_stem),
        block_count: 0,
        starting_exponent: 0,
    });

    let exponent_width = recovery_block_count.to_string().len().max(2);
    let power_width = calculate_par2_padding_width(recovery_block_count);

    while remaining > 0 {
        if !remaining.is_multiple_of(2) {
            files.push(Par2FileSpec {
                file_name: format!(
                    "{}.vol{:0>ew$}+{:0>pw$}.par2",
                    file_stem,
                    current_exponent,
                    power,
                    ew = exponent_width,
                    pw = power_width
                ),
                block_count: power,
                starting_exponent: current_exponent,
            });

            current_exponent += power;
        }

        remaining = remaining.div(2);
        power = power.mul(2);
    }

    Ok(files)
}

/// Calculates how many digits of zero-padding are needed for PAR2 filenames.
/// PAR2 files grow in powers of 2 (1, 2, 4, 8...). This finds the decimal
/// length of the largest power of 2 that fits in `total_blocks`.
fn calculate_par2_padding_width(recovery_block_count: u16) -> usize {
    if recovery_block_count == 0 {
        return 1; // Fallback to 1 digit if there are 0 blocks
    }

    // ilog2 finds the highest power of exponent 2, and `1 << x` calculates that value.
    let largest_power_of_two = 1 << recovery_block_count.ilog2();

    largest_power_of_two.to_string().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod get_sanitized_file_path {
        use super::*;

        #[test]
        fn rejects_parent_paths() {
            let base_path = Path::new("/test");
            let input_path = "../file.txt";

            let result = get_sanitized_file_path(&base_path, &input_path);
            let err = result.unwrap_err();

            assert!(matches!(err, Par2Error::FilePathError(_)));
            assert_eq!(
                err.to_string(),
                "file \"../file.txt\" contains unsupported path",
            );
        }

        #[test]
        fn rejects_absolute_paths() {
            let base_path = Path::new("/test");
            let input_path = "/file.txt";

            let result = get_sanitized_file_path(&base_path, &input_path);
            let err = result.unwrap_err();

            assert!(matches!(err, Par2Error::FilePathError(_)));
            assert_eq!(
                err.to_string(),
                "file \"/file.txt\" contains unsupported path",
            );
        }

        #[cfg(target_os = "windows")]
        #[test]
        fn rejects_prefixed_paths() {
            let base_path = Path::new("/test");
            let input_path = "C:\\file.txt";

            let result = get_sanitized_file_path(&base_path, &input_path);
            let err = result.unwrap_err();

            assert!(matches!(err, Par2Error::FilePathError(_)));
            assert_eq!(
                err.to_string(),
                "file \"C:\\file.txt\" contains unsupported path",
            );
        }

        #[test]
        fn rejects_empty_paths() {
            let base_path = Path::new("/test");
            let input_path = "./.";

            let result = get_sanitized_file_path(&base_path, &input_path);
            let err = result.unwrap_err();

            assert!(matches!(err, Par2Error::FilePathError(_)));
            assert_eq!(err.to_string(), "file \"./.\" resolved to empty path");
        }

        #[test]
        fn normalizes_weird_paths() {
            let base_path = Path::new("/test");
            let input_path = "./why/./file.txt";

            let result = get_sanitized_file_path(&base_path, &input_path);
            let output = result.unwrap();

            assert_eq!(output, PathBuf::from("/test/why/file.txt"));
        }
    }

    mod plan_recovery_files {
        use super::*;

        #[test]
        fn produces_expected_output() {
            let path = Path::new("test.dat");
            let files = plan_recovery_files(path, 15).expect("failed to build recovery files");

            assert_eq!(
                files,
                vec![
                    Par2FileSpec {
                        file_name: "test.par2".into(),
                        starting_exponent: 0,
                        block_count: 0
                    },
                    Par2FileSpec {
                        file_name: "test.vol00+1.par2".into(),
                        starting_exponent: 0,
                        block_count: 1
                    },
                    Par2FileSpec {
                        file_name: "test.vol01+2.par2".into(),
                        starting_exponent: 1,
                        block_count: 2
                    },
                    Par2FileSpec {
                        file_name: "test.vol03+4.par2".into(),
                        starting_exponent: 3,
                        block_count: 4
                    },
                    Par2FileSpec {
                        file_name: "test.vol07+8.par2".into(),
                        starting_exponent: 7,
                        block_count: 8
                    },
                ]
            );
        }

        #[test]
        fn has_consistent_padding() {
            let path = Path::new("test.dat");
            let files = plan_recovery_files(path, 127).expect("failed to build recovery files");

            assert_eq!(files.len(), 8);
            assert_eq!(files[1].file_name, "test.vol000+01.par2");
            assert_eq!(files[7].file_name, "test.vol063+64.par2");
        }
    }
}
