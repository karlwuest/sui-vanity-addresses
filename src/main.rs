use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::Parser;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use sui_keys::{key_derive::generate_new_key, keypair_file::write_keypair_to_file};
use sui_types::crypto::SignatureScheme;

const DEFAULT_N_PER_ROUND: usize = 10000;

#[derive(Parser)]
struct CliArgs {
    /// Number of keys to generate per round. This determines how many keys are generated
    /// in parallel and how quickly the program will provide progress output.
    #[arg(long, default_value_t = DEFAULT_N_PER_ROUND)]
    addresses_per_round: usize,
    /// Number of vanity addresses to generate. If provided, the program will stop at the
    /// end of the round after finding the specified number of vanity addresses.
    /// The program may still output more than the specified number of vanity addresses if it
    /// finds additional addresses in a single round.
    #[arg(short, long, default_value_t = 1)]
    n_vanity_addresses: usize,
    /// A string that the vanity address must start with. This string will be converted to
    /// closely matching hexspeak characters. Alternatively, a hex prefix can be provided
    /// that must start with `0x`.
    vanity_prefix: String,
    /// The output directory to write the keys to.
    #[arg(short, long, default_value = ".")]
    output_dir: PathBuf,
}

fn string_to_hexspeak(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Hexspeak lookup table: maps lowercase characters to similar-looking hex characters
    let hexspeak_map: std::collections::HashMap<char, char> = [
        ('a', 'a'),
        ('b', 'b'),
        ('c', 'c'),
        ('d', 'd'),
        ('e', 'e'),
        ('f', 'f'),
        ('g', '9'),
        ('i', '1'),
        ('j', '1'),
        ('l', '1'),
        ('o', '0'),
        ('q', '9'),
        ('s', '5'),
        ('t', '7'),
        ('z', '2'),
        // Digits map to themselves
        ('0', '0'),
        ('1', '1'),
        ('2', '2'),
        ('3', '3'),
        ('4', '4'),
        ('5', '5'),
        ('6', '6'),
        ('7', '7'),
        ('8', '8'),
        ('9', '9'),
    ]
    .iter()
    .cloned()
    .collect();

    let mut hex_string = String::new();

    // Convert input to lowercase first
    let lowercase_s = s.to_lowercase();

    for c in lowercase_s.chars() {
        if let Some(&hex_char) = hexspeak_map.get(&c) {
            hex_string.push(hex_char);
        } else {
            return Err(format!("Cannot map character '{}' to hexspeak", c).into());
        }
    }

    hex_str_to_bytes(&hex_string)
}

// Convert hex string to bytes
fn hex_str_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex_str = hex_str.trim_start_matches("0x");

    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let end = std::cmp::min(i + 2, hex_str.len());
        let hex_pair = &hex_str[i..end];
        // Pad with '0' if we have an odd number of characters
        let padded_hex = if hex_pair.len() == 1 {
            format!("{}0", hex_pair)
        } else {
            hex_pair.to_string()
        };
        bytes.push(
            u8::from_str_radix(&padded_hex, 16)
                .map_err(|_| format!("Invalid hex string: {}", padded_hex))?,
        );
    }

    Ok(bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();
    generate_vanity_addresses(
        &args.vanity_prefix,
        &args.output_dir,
        args.n_vanity_addresses,
        args.addresses_per_round,
    )?;
    Ok(())
}

fn generate_vanity_addresses(
    vanity_prefix: &str,
    output_dir: &Path,
    n_vanity_addresses: usize,
    addresses_per_round: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut needle = if vanity_prefix.starts_with("0x") {
        hex_str_to_bytes(&vanity_prefix)?
    } else {
        string_to_hexspeak(&vanity_prefix)?
    };
    let uneven_last_nibble = if vanity_prefix.len() % 2 == 1 {
        needle.pop()
    } else {
        None
    };
    let scheme = SignatureScheme::ED25519;
    let count = AtomicUsize::new(0);
    let mut tried = 0;

    while count.load(Ordering::Relaxed) < n_vanity_addresses {
        (0..addresses_per_round).into_par_iter().for_each(|_| {
            let (sui_address, skp, _scheme, _phrase) =
                generate_new_key(scheme, None, None).expect("generate_new_key should not fail");
            if sui_address.as_ref().starts_with(&needle) {
                if let Some(uneven_last_nibble) = uneven_last_nibble {
                    let relevant_nibble = sui_address.as_ref()[needle.len()] & 0xf0;
                    if relevant_nibble != uneven_last_nibble {
                        return;
                    }
                }
                let file = output_dir.join(format!("{sui_address}.key"));
                write_keypair_to_file(&skp, file).expect("write_keypair_to_file should not fail");
                println!("Found match: {sui_address}");
                count.fetch_add(1, Ordering::Relaxed);
            }
        });
        tried += addresses_per_round;
        println!("Tried: {tried}");
        io::stdout().flush().expect("flush stdout");
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hex_str_to_bytes() {
        // Basic hex conversion
        assert_eq!(
            hex_str_to_bytes("48656c6c6f").unwrap(),
            vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]
        ); // "Hello"
        assert_eq!(hex_str_to_bytes("ff").unwrap(), vec![0xff]);
        assert_eq!(hex_str_to_bytes("AaBbCc").unwrap(), vec![0xaa, 0xbb, 0xcc]);

        // With 0x prefix
        assert_eq!(
            hex_str_to_bytes("0x48656c6c6f").unwrap(),
            vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]
        );

        // Edge cases
        assert_eq!(hex_str_to_bytes("").unwrap(), vec![] as Vec<u8>);
        assert_eq!(hex_str_to_bytes("a").unwrap(), vec![0xa0]); // "a0" padded

        // Invalid hex
        assert!(hex_str_to_bytes("gg").is_err());
    }

    #[test]
    fn test_string_to_hexspeak() {
        // Basic hexspeak conversion
        assert_eq!(string_to_hexspeak("dead").unwrap(), vec![0xde, 0xad]);
        assert_eq!(string_to_hexspeak("beef").unwrap(), vec![0xbe, 0xef]);
        assert_eq!(string_to_hexspeak("cool").unwrap(), vec![0xc0, 0x01]);

        // Case insensitive
        assert_eq!(string_to_hexspeak("DeAd").unwrap(), vec![0xde, 0xad]);

        // All character mappings
        assert_eq!(
            string_to_hexspeak("abcdefgijloqstz").unwrap(),
            vec![0xab, 0xcd, 0xef, 0x91, 0x11, 0x09, 0x57, 0x20,]
        );

        // Edge cases
        assert_eq!(string_to_hexspeak("").unwrap(), vec![] as Vec<u8>);

        // Invalid characters
        assert!(string_to_hexspeak("hello!").is_err());
        assert!(string_to_hexspeak("dead beef").is_err());
        assert!(string_to_hexspeak("dead@beef").is_err());

        // Mixed alphanumeric should work
        assert_eq!(
            string_to_hexspeak("dead123").unwrap(),
            vec![0xde, 0xad, 0x12, 0x30]
        );
    }

    fn generate_vanity_addresses_helper(hex_vanity_prefix: &str, n_vanity_addresses: usize) {
        let temp_dir = tempfile::tempdir().unwrap();
        generate_vanity_addresses(hex_vanity_prefix, &temp_dir.path(), n_vanity_addresses, 100)
            .unwrap();
        let files = temp_dir
            .path()
            .read_dir()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(files.len() >= n_vanity_addresses);
        assert!(files.iter().all(|f| f
            .file_name()
            .to_str()
            .unwrap()
            .starts_with(hex_vanity_prefix)));
    }

    #[test]
    fn test_generate_vanity_addresses() {
        generate_vanity_addresses_helper("0x12", 1);
    }

    #[test]
    fn test_generate_vanity_addresses_with_uneven_last_nibble() {
        generate_vanity_addresses_helper("0x1", 1);
    }
}
