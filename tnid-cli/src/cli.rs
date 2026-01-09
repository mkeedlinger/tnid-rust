use clap::{Parser, Subcommand};

/// TNID CLI - Generate, parse, and manipulate TNIDs
#[derive(Parser)]
#[command(name = "tnid")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new TNID
    Generate {
        /// The TNID name (1-4 characters, digits 0-4 and lowercase a-z only)
        name: String,

        /// Generate a V1 (random) TNID instead of V0 (time-ordered)
        #[arg(long)]
        v1: bool,
    },

    /// Parse a TNID and show basic information
    Parse {
        /// The TNID to parse (TNID or UUID format)
        id: String,
    },

    /// Encrypt a V0 TNID to V1
    Encrypt {
        /// The TNID to encrypt
        id: String,

        /// 32-character hex encryption key
        key: String,
    },

    /// Decrypt a V1 TNID to V0
    Decrypt {
        /// The TNID to decrypt
        id: String,

        /// 32-character hex encryption key
        key: String,
    },

    /// Show detailed TNID information
    Inspect {
        /// The TNID to inspect (TNID or UUID format)
        id: String,
    },

    /// Validate a TNID name
    Validate {
        /// The name to validate
        name: String,
    },
}
