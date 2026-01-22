mod cli;

use clap::Parser;
use cli::{Cli, InternalCli, OutputFormat};
use tnid::{encryption::EncryptionKey, internals, Case, DynamicTnid, NameStr, TnidVariant};

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
        eprintln!(
            "Error: input doesn't look like a TNID string (expected format: name.data) or UUID (expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        );
        std::process::exit(1);
    }
}

fn parse_hex_u128(hex: &str) -> u128 {
    let clean_hex = hex.trim_start_matches("0x");
    match u128::from_str_radix(clean_hex, 16) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing hex string '{}': {}", hex, e);
            std::process::exit(1);
        }
    }
}

fn handle_internal(cmd: InternalCli) {
    match cmd {
        InternalCli::EncodeName { name } => match NameStr::new(&name) {
            Ok(n) => {
                let mask = internals::name_mask(n);
                println!("{}", internals::name_bits_to_hex(mask));
            }
            Err(e) => {
                eprintln!("Error: invalid name: {}", e);
                std::process::exit(1);
            }
        },

        InternalCli::DecodeName { name_hex } => {
            let name_bits_val = parse_hex_u128(&name_hex);
            let id = name_bits_val << 108;
            match internals::extract_name_string(id) {
                Some(n) => println!("{}", n),
                None => {
                    eprintln!("Error: invalid name bits");
                    std::process::exit(1);
                }
            }
        }

        InternalCli::MakeV0 {
            name,
            timestamp,
            random,
        } => {
            let name_str = match NameStr::new(&name) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error: invalid name: {}", e);
                    std::process::exit(1);
                }
            };
            let id = DynamicTnid::new_v0_with_parts(name_str, timestamp, random);
            println!("{}", id.to_tnid_string());
        }

        InternalCli::MakeV1 { name, random } => {
            let name_str = match NameStr::new(&name) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Error: invalid name: {}", e);
                    std::process::exit(1);
                }
            };
            let random_val = parse_hex_u128(&random);
            let id = DynamicTnid::new_v1_with_random(name_str, random_val);
            println!("{}", id.to_tnid_string());
        }

        InternalCli::ExtractDataBits { id } => {
            let tnid = parse_tnid(&id);
            let bits = internals::extract_data_bits(tnid.as_u128());
            println!("0x{:026x}", bits);
        }

        InternalCli::ExpandDataBits { bits } => {
            let bits_val = parse_hex_u128(&bits);
            let expanded = internals::expand_data_bits(bits_val);
            println!("0x{:032x}", expanded);
        }

        InternalCli::ExtractSecretDataBits { id } => {
            let tnid = parse_tnid(&id);
            let bits = internals::extract_secret_data_bits(tnid.as_u128());
            println!("0x{:025x}", bits);
        }

        InternalCli::ExpandSecretDataBits { bits } => {
            let bits_val = parse_hex_u128(&bits);
            let expanded = internals::expand_secret_data_bits(bits_val);
            println!("0x{:032x}", expanded);
        }

        InternalCli::StringToIdData { string } => match internals::string_to_id_data(&string) {
            Ok(bits) => println!("0x{:026x}", bits),
            Err(e) => {
                eprintln!("Error decoding data string: {}", e);
                std::process::exit(1);
            }
        },

        InternalCli::EncryptRaw { data, key } => {
            let data_val = parse_hex_u128(&data);
            let encryption_key = match EncryptionKey::from_hex(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error parsing encryption key: {}", e);
                    std::process::exit(1);
                }
            };
            let encrypted = internals::encrypt(data_val, &encryption_key);
            println!("0x{:025x}", encrypted);
        }

        InternalCli::DecryptRaw { data, key } => {
            let data_val = parse_hex_u128(&data);
            let encryption_key = match EncryptionKey::from_hex(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error parsing encryption key: {}", e);
                    std::process::exit(1);
                }
            };
            let decrypted = internals::decrypt(data_val, &encryption_key);
            println!("0x{:025x}", decrypted);
        }

        InternalCli::ChangeVariant { id, variant } => {
            let tnid = parse_tnid(&id);
            let variant_enum = match variant {
                0 => TnidVariant::V0,
                1 => TnidVariant::V1,
                2 => TnidVariant::V2,
                3 => TnidVariant::V3,
                _ => {
                    eprintln!("Error: variant must be 0-3");
                    std::process::exit(1);
                }
            };
            let new_id_val = internals::change_variant(tnid.as_u128(), variant_enum);
            match DynamicTnid::from_u128(new_id_val) {
                Ok(t) => println!("{}", t.to_tnid_string()),
                Err(_) => {
                    println!("0x{:032x}", new_id_val);
                }
            }
        }

        InternalCli::EncodeV0Timestamp { millis } => {
            let mask = internals::v0_millis_mask(millis);
            println!("0x{:032x}", mask);
        }

        InternalCli::EncodeV0Random { random } => {
            let mask = internals::v0_random_bits_mask(random);
            println!("0x{:032x}", mask);
        }

        InternalCli::EncodeV1Random { random } => {
            let random_val = parse_hex_u128(&random);
            let mask = internals::v1_random_bits_mask(random_val);
            println!("0x{:032x}", mask);
        }

        InternalCli::CompactDataToString { bits } => {
            let bits_val = parse_hex_u128(&bits);
            // We need to expand bits to their proper position first
            let expanded = internals::expand_data_bits(bits_val);
            println!("{}", internals::id_data_to_string(expanded));
        }

        InternalCli::U128ToUuid { u128_hex, upper } => {
            let val = parse_hex_u128(&u128_hex);
            let case = if upper { Case::Upper } else { Case::Lower };
            println!("{}", internals::u128_to_uuid_string(val, case));
        }

        InternalCli::ShowConstants => {
            println!("--- Name Encoding ---");
            println!("NAME_MIN_CHARS:        {}", internals::NAME_MIN_CHARS);
            println!("NAME_MAX_CHARS:        {}", internals::NAME_MAX_CHARS);
            println!("NAME_CHAR_BIT_LENGTH:  {}", internals::NAME_CHAR_BIT_LENGTH);
            println!("NON_NAME_BITS:         {}", internals::NON_NAME_BITS);
            println!("NAME_CHAR_MAPPING:");
            for (val, char_code) in internals::NAME_CHAR_MAPPING {
                println!("  {:2}: '{}'", val, char_code as char);
            }

            println!("\n--- Data Encoding ---");
            println!("DATA_BIT_NUM:           {}", internals::DATA_BIT_NUM);
            println!(
                "DATA_CHAR_ENCODING_LEN: {}",
                internals::DATA_CHAR_ENCODING_LEN
            );
            println!(
                "DATA_CHAR_BIT_LENGTH:   {}",
                internals::DATA_CHAR_BIT_LENGTH
            );
            println!(
                "RIGHT_DATA_SECTION_MASK:  0x{:032x}",
                internals::RIGHT_DATA_SECTION_MASK
            );
            println!(
                "MIDDLE_DATA_SECTION_MASK: 0x{:032x}",
                internals::MIDDLE_DATA_SECTION_MASK
            );
            println!(
                "LEFT_DATA_SECTION_MASK:   0x{:032x}",
                internals::LEFT_DATA_SECTION_MASK
            );
            println!("DATA_CHAR_MAPPING:");
            for (val, char_code) in internals::DATA_CHAR_MAPPING {
                println!("  {:2}: '{}'", val, char_code as char);
            }

            println!("\n--- UUID / Variant Metadata ---");
            println!(
                "UUID_V8_MASK:             0x{:032x}",
                internals::UUID_V8_MASK
            );

            println!("\n--- Encryption ---");
            println!(
                "RIGHT_SECRET_DATA_SECTION_MASK:  0x{:032x}",
                internals::RIGHT_SECRET_DATA_SECTION_MASK
            );
            println!(
                "MIDDLE_SECRET_DATA_SECTION_MASK: 0x{:032x}",
                internals::MIDDLE_SECRET_DATA_SECTION_MASK
            );
            println!(
                "LEFT_SECRET_DATA_SECTION_MASK:   0x{:032x}",
                internals::LEFT_SECRET_DATA_SECTION_MASK
            );
            println!(
                "COMPLETE_SECRET_DATA_MASK:       0x{:032x}",
                internals::COMPLETE_SECRET_DATA_MASK
            );

            println!("\n--- V0 ---");
            println!(
                "V0_TIMESTAMP_FIRST_28_MASK:  0x{:016x}",
                internals::V0_TIMESTAMP_FIRST_28_MASK
            );
            println!(
                "V0_TIMESTAMP_SECOND_12_MASK: 0x{:016x}",
                internals::V0_TIMESTAMP_SECOND_12_MASK
            );
            println!(
                "V0_TIMESTAMP_LAST_3_MASK:    0x{:016x}",
                internals::V0_TIMESTAMP_LAST_3_MASK
            );
            println!(
                "V0_RANDOM_MASK:              0x{:032x}",
                internals::V0_RANDOM_MASK
            );

            println!("\n--- V1 ---");
            println!(
                "V1_RANDOM_MASK:              0x{:032x}",
                internals::V1_RANDOM_MASK
            );
        }
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

        Cli::ValidateName { name } => match NameStr::new(&name) {
            Ok(_) => println!("valid"),
            Err(e) => {
                println!("invalid: {}", e);
                std::process::exit(1);
            }
        },

        Cli::Internals(cmd) => handle_internal(cmd),
    }
}
