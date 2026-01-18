mod cli;

use clap::Parser;
use cli::{Cli, OutputFormat};
use tnid::{encryption::EncryptionKey, Case, DynamicTnid, NameStr, TnidVariant};

fn parse_tnid(id: &str) -> DynamicTnid {
    if id.contains('.') {
        match DynamicTnid::parse_tnid_string(id) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error parsing TNID string: {}", e);
                std::process::exit(1);
            }
        }
    } else if id.contains('-') {
        match DynamicTnid::parse_uuid_string(id) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error parsing UUID string: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error: input doesn't look like a TNID string (expected format: name.data) or UUID (expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
        std::process::exit(1);
    }
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Generate {
            name,
            variant,
            output,
        } => {
            let name = match NameStr::new(&name) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let id = match variant {
                0 => DynamicTnid::new_v0(name),
                1 => DynamicTnid::new_v1(name),
                2 | 3 => {
                    eprintln!("Error: variant {} is reserved for future use", variant);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Error: variant must be 0-3, got {}", variant);
                    std::process::exit(1);
                }
            };

            match output {
                OutputFormat::Tnid => println!("{}", id.to_tnid_string()),
                OutputFormat::Uuid => println!("{}", id.to_uuid_string(Case::Lower)),
                OutputFormat::U128 => println!("0x{:032x}", id.as_u128()),
            }
        }

        Cli::Encrypt {
            id,
            key,
            passthrough,
        } => {
            let tnid = parse_tnid(&id);

            // Parse the key
            let encryption_key = match EncryptionKey::from_hex(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error parsing encryption key: {}", e);
                    std::process::exit(1);
                }
            };

            // Check variant
            match tnid.variant() {
                TnidVariant::V0 => {
                    // Encrypt V0 to V1
                    let encrypted = match tnid.encrypt_v0_to_v1(encryption_key) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("Error encrypting TNID: {}", e);
                            std::process::exit(1);
                        }
                    };
                    println!("{}", encrypted.to_tnid_string());
                }
                TnidVariant::V1 => {
                    if passthrough {
                        // Pass through unchanged
                        println!("{}", tnid.to_tnid_string());
                    } else {
                        eprintln!("Error: TNID is already V1");
                        std::process::exit(1);
                    }
                }
                variant => {
                    eprintln!("Error: cannot encrypt variant {:?}", variant);
                    std::process::exit(1);
                }
            }
        }

        Cli::Decrypt {
            id,
            key,
            passthrough,
        } => {
            let tnid = parse_tnid(&id);

            // Parse the key
            let encryption_key = match EncryptionKey::from_hex(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error parsing encryption key: {}", e);
                    std::process::exit(1);
                }
            };

            // Check variant
            match tnid.variant() {
                TnidVariant::V1 => {
                    // Decrypt V1 to V0
                    let decrypted = match tnid.decrypt_v1_to_v0(encryption_key) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("Error decrypting TNID: {}", e);
                            std::process::exit(1);
                        }
                    };
                    println!("{}", decrypted.to_tnid_string());
                }
                TnidVariant::V0 => {
                    if passthrough {
                        // Pass through unchanged
                        println!("{}", tnid.to_tnid_string());
                    } else {
                        eprintln!("Error: TNID is already V0");
                        std::process::exit(1);
                    }
                }
                variant => {
                    eprintln!("Error: cannot decrypt variant {:?}", variant);
                    std::process::exit(1);
                }
            }
        }

        Cli::Inspect { id } => {
            let tnid = parse_tnid(&id);

            println!("name: {}", tnid.name());
            println!("name_hex: {}", tnid.name_hex());
            println!("variant: {:?}", tnid.variant());
            println!("tnid_string: {}", tnid.to_tnid_string());
            println!("uuid_string: {}", tnid.to_uuid_string(Case::Lower));
        }

        Cli::ValidateName { name } => {
            match NameStr::new(&name) {
                Ok(_) => println!("valid"),
                Err(e) => {
                    println!("invalid: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Cli::EncodeName { name } => {
            todo!("Encode name: {}", name);
        }

        Cli::DecodeName { name_hex } => {
            todo!("Decode name hex: {}", name_hex);
        }
    }
}
