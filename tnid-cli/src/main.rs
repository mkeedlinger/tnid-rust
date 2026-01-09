mod cli;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { name, v1 } => {
            todo!("Generate TNID with name: {}, v1: {}", name, v1);
        }

        Commands::Parse { id } => {
            todo!("Parse TNID: {}", id);
        }

        Commands::Encrypt { id, key } => {
            todo!("Encrypt TNID: {} with key: {}", id, key);
        }

        Commands::Decrypt { id, key } => {
            todo!("Decrypt TNID: {} with key: {}", id, key);
        }

        Commands::Inspect { id } => {
            todo!("Inspect TNID: {}", id);
        }

        Commands::Validate { name } => {
            todo!("Validate name: {}", name);
        }
    }
}
