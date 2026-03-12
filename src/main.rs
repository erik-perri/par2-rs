mod cli;
mod error;
mod file;
mod file_name;
mod galois;
mod packet;
mod set;
mod verify;

use clap::{Parser, Subcommand};
use colored::Colorize;
use log::error;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "par2")]
#[command(about = "PAR2 file creation and repair")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    verbose: u8,
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

    let level = match cli.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp(None)
        .format_target(false)
        .format_level(format_level(cli.verbose))
        .init();

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
        match e {
            error::Par2Error::RepairRequired => process::exit(1),
            _ => {
                error!("{}: {}", "Error".bold().red(), e);
                process::exit(1);
            }
        }
    }

    process::exit(0);
}

fn format_level(verbose: u8) -> bool {
    verbose > 0
}
