use std::path::{Path, PathBuf};
use std::process;

pub(crate) fn create(
    _block_size: u64,
    _recovery_block_count: u16,
    _output: &Path,
    _files: &[PathBuf],
) {
    println!("not implemented");
    process::exit(1);
}
