use clap::{Parser, ValueEnum};

const KEY_NAME: &str = "TNID_KEY";

/// Output format for generated TNIDs
#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    /// TNID string format: name.encodeddata
    Tnid,
    /// UUID hex format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Uuid,
    /// Raw 128-bit hex: 0x00000000000000000000000000000000
    U128,
}

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
    ///   user.BsOdOgguzJorJeVH7
    ///
    ///   $ tnid generate user -n 1
    ///
    ///   user.8z099cGumNjXw8whQ
    ///
    ///   $ tnid generate user -o uuid
    ///
    ///   d6157338-6696-8b69-895b-2e3528a74163
    Generate {
        /// The TNID name (1-4 characters, digits 0-4 and lowercase a-z only)
        name: String,

        /// Which variant to generate (0-3)
        #[arg(short = 'n', long, default_value_t = 0)]
        variant: u8,

        /// Output format: tnid (default), uuid, or u128
        #[arg(short = 'o', long, default_value = "tnid")]
        output: OutputFormat,
    },

    /// Encrypt a V0 TNID to V1
    ///
    /// The key can be provided as an argument or via the TNID_KEY environment variable.
    ///
    /// Examples:
    ///
    ///   $ tnid encrypt user.BsOdOgguzJorJeVH7 0102030405060708090a0b0c0d0e0f10
    ///
    ///   user.-8hAMlKY0mjrmzQHv
    ///
    ///   $ TNID_KEY=0102030405060708090a0b0c0d0e0f10 tnid encrypt user.BsOdOgguzJorJeVH7
    ///
    ///   user.-8hAMlKY0mjrmzQHv
    Encrypt {
        /// The TNID to encrypt
        id: String,

        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,

        /// Pass through V1 TNIDs unchanged instead of erroring
        #[arg(short, long, default_value_t = false)]
        passthrough: bool,
    },

    /// Decrypt a V1 TNID to V0
    ///
    /// The key can be provided as an argument or via the TNID_KEY environment variable.
    ///
    /// Examples:
    ///
    ///   $ tnid decrypt user.-8hAMlKY0mjrmzQHv 0102030405060708090a0b0c0d0e0f10
    ///
    ///   user.BsOdOgguzJorJeVH7
    Decrypt {
        /// The TNID to decrypt
        id: String,

        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,

        /// Pass through V0 TNIDs unchanged instead of erroring
        #[arg(short, long, default_value_t = false)]
        passthrough: bool,
    },

    /// Show detailed TNID information
    ///
    /// Accepts both TNID and UUID format as input.
    ///
    /// Examples:
    ///
    ///   $ tnid inspect user.BsOdOgguzJorJeVH7
    ///
    ///   name: user
    ///
    ///   name_hex: d6157
    ///
    ///   variant: V0
    ///
    ///   tnid_string: user.BsOdOgguzJorJeVH7
    ///
    ///   uuid_string: d6157338-6696-86cb-8ebf-534dd4aa0488
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
    ///   invalid: invalid character 'U' (0x55) in name; only 0-4 and a-z are allowed
    ValidateName {
        /// The name to validate
        name: String,
    },

    /// Internal debug and verification commands
    ///
    /// Low-level commands for debugging the TNID spec. Not needed for normal use.
    #[command(subcommand)]
    Internals(InternalCli),
}

#[derive(clap::Subcommand)]
pub enum InternalCli {
    /// Convert a TNID name to its hex encoding
    ///
    /// Examples:
    ///
    ///   $ tnid internals encode-name user
    ///
    ///   d6157
    EncodeName {
        /// The name to encode
        name: String,
    },

    /// Convert a hex encoding to its TNID name
    ///
    /// Examples:
    ///
    ///   $ tnid internals decode-name d6157
    ///
    ///   user
    DecodeName {
        /// The hex encoding to decode (5 hex characters)
        name_hex: String,
    },

    /// Manually construct a V0 TNID from parts
    MakeV0 {
        /// The TNID name
        name: String,
        /// Epoch milliseconds (hex)
        timestamp: String,
        /// Random bits (hex)
        random: String,
    },

    /// Manually construct a V1 TNID from parts
    MakeV1 {
        /// The TNID name
        name: String,
        /// Random bits (u128 hex)
        random: String,
    },

    /// Extract the Data bits (102 bits) from a TNID
    ExtractDataBits {
        /// The TNID to extract from
        id: String,
    },

    /// Expand compact Data bits (102 bits) to their position in a 128-bit TNID
    ExpandDataBits {
        /// Compact Data bits (hex)
        bits: String,
    },

    /// Extract the Payload bits (100 bits) from a TNID
    ExtractSecretDataBits {
        /// The TNID to extract from
        id: String,
    },

    /// Expand compact Payload bits (100 bits) to their position in a 128-bit TNID
    ExpandSecretDataBits {
        /// Compact Payload bits (hex)
        bits: String,
    },

    /// Decode a data string to its raw bits
    StringToIdData {
        /// The data string (part after the dot)
        string: String,
    },

    /// Encrypt raw Payload bits (100 bits) using FF1
    EncryptRaw {
        /// Payload bits to encrypt (hex)
        data: String,
        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,
    },

    /// Decrypt raw Payload bits (100 bits) using FF1
    DecryptRaw {
        /// Payload bits to decrypt (hex)
        data: String,
        /// 32-character hex encryption key
        #[arg(env = KEY_NAME)]
        key: String,
    },

    /// Change the variant of a TNID
    ChangeVariant {
        /// The TNID to modify
        id: String,
        /// The new variant (0-3)
        variant: u8,
    },

    /// Encode a V0 timestamp to its scattered bit positions
    EncodeV0Timestamp {
        /// Timestamp in milliseconds since epoch (hex)
        millis: String,
    },

    /// Encode V0 random bits to their scattered bit positions
    EncodeV0Random {
        /// Random bits (hex)
        random: String,
    },

    /// Encode V1 random bits to their scattered bit positions
    EncodeV1Random {
        /// Random bits (u128 hex)
        random: String,
    },

    /// Convert compact Data bits (102 bits) to a TNID data string
    CompactDataToString {
        /// Compact Data bits (hex)
        bits: String,
    },

    /// Convert a 128-bit value to a standard UUID string
    U128ToUuid {
        /// The u128 value to format (hex)
        u128_hex: String,
        /// Use uppercase hex digits (A-F)
        #[arg(short, long, default_value_t = false)]
        upper: bool,
    },

    /// Show all internal constants (masks, mappings, etc.)
    ShowConstants,
}
