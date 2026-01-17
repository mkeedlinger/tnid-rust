use clap::Parser;

const KEY_NAME: &str = "TNID_KEY";

/// TNID - Generate, parse, and manipulate TNIDs
#[derive(Parser)]
#[command(name = "tnid")]
#[command(version, about, long_about = None)]
pub enum Cli {
    /// Generate a new TNID
    ///
    /// Examples:
    ///
    ///   $ tnid generate user
    ///
    ///   user_01jh5p8zqk0000000000000000
    ///
    ///   $ tnid generate post -n 1
    ///
    ///   post_01jh5p8zqk1111111111111111
    Generate {
        /// The TNID name (1-4 characters, digits 0-4 and lowercase a-z only)
        name: String,

        /// Which variant to generate (0-3)
        #[arg(short = 'n', long, default_value_t = 0)]
        variant: u8,
    },

    /// Encrypt a V0 TNID to V1
    ///
    /// Examples:
    ///
    ///   $ tnid encrypt user_01jh5p8zqk0000000000000000 0102030405060708090a0b0c0d0e0f10
    ///
    ///   user_01jh5p8zqk1234567890abcdef
    ///
    ///   $ TNID_KEY=0102030405060708090a0b0c0d0e0f10 tnid encrypt user_01jh5p8zqk0000000000000000
    ///
    ///   user_01jh5p8zqk1234567890abcdef
    Encrypt {
        /// The TNID to encrypt
        id: String,

        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,
    },

    /// Decrypt a V1 TNID to V0
    ///
    /// Examples:
    ///
    ///   $ tnid decrypt user_01jh5p8zqk1234567890abcdef 0102030405060708090a0b0c0d0e0f10
    ///
    ///   user_01jh5p8zqk0000000000000000
    Decrypt {
        /// The TNID to decrypt
        id: String,

        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,
    },

    /// Show detailed TNID information
    ///
    /// Examples:
    ///
    ///   $ tnid inspect user_01jh5p8zqk0000000000000000
    ///
    ///   name: user
    ///   name_hex: 19a80
    ///   variant: V0
    ///   tnid_string: user_01jh5p8zqk0000000000000000
    ///   uuid_string: cab19528-f09d-86d9-928e-96ea03dc6af3
    ///   timestamp: 2025-01-09T12:34:56.789Z
    Inspect {
        /// The TNID to inspect (TNID or UUID format)
        id: String,
    },

    /// Validate a TNID name string
    ///
    /// Examples:
    ///
    ///   $ tnid validate-name user
    ///
    ///   valid
    ///
    ///   $ tnid validate-name User
    ///
    ///   invalid: uppercase not allowed
    ///
    ///   $ tnid validate-name abc9
    ///
    ///   invalid: digit 9 not allowed (only 0-4)
    ValidateName {
        /// The name to validate
        name: String,
    },

    /// Convert a TNID name to its hex encoding
    ///
    /// Examples:
    ///
    ///   $ tnid encode-name user
    ///
    ///   19a80
    ///
    ///   $ tnid encode-name a
    ///
    ///   06000
    EncodeName {
        /// The name to encode
        name: String,
    },

    /// Convert a hex encoding to its TNID name
    ///
    /// Examples:
    ///
    ///   $ tnid decode-name 19a80
    ///
    ///   user
    ///
    ///   $ tnid decode-name 06000
    ///
    ///   a
    DecodeName {
        /// The hex encoding to decode (5 hex characters)
        name_hex: String,
    },
}
