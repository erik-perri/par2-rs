mod cli;
mod error;
mod file;
mod file_name;
mod galois;
mod packet;
mod set;
mod verify;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "par2")]
#[command(about = "PAR2 file creation and repair")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        #[arg(short = 's', long, default_value = "16")]
        block_size: u64,
        #[arg(short = 'c', long, default_value = "2")]
        recovery_block_count: u16,
        #[arg(long, default_value = "testing")]
        creator: String,
        #[arg(required = true)]
        output: PathBuf,
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    Verify {
        file: PathBuf,
    },

    Repair {
        file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Create {
            block_size,
            recovery_block_count,
            output,
            files,
            creator,
        } => cli::create(block_size, recovery_block_count, &output, &files, &creator),
        Commands::Verify { file } => cli::verify(&file),
        Commands::Repair { file } => cli::repair(&file),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    process::exit(0);
}
