mod cli;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Generate { name, variant } => {
            todo!("Generate TNID with name: {}, variant: {}", name, variant);
        }

        Cli::Encrypt { id, key } => {
            todo!("Encrypt TNID: {} with key: {}", id, key);
        }

        Cli::Decrypt { id, key } => {
            todo!("Decrypt TNID: {} with key: {}", id, key);
        }

        Cli::Inspect { id } => {
            todo!("Inspect TNID: {}", id);
        }

        Cli::ValidateName { name } => {
            todo!("Validate name: {}", name);
        }

        Cli::EncodeName { name } => {
            todo!("Encode name: {}", name);
        }

        Cli::DecodeName { name_hex } => {
            todo!("Decode name hex: {}", name_hex);
        }
    }
}
