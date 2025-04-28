use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::OsRng};
use clap::{Parser, Subcommand};
use crypto::{
    CurveParams, CurveType, compute_secret_key, generate_random_seed, key_and_nonce_to_string,
    retrieve_from_secret_key, string_to_key_and_nonce,
};
use error::FileShadowError;

mod crypto;
mod error;
mod hide;
mod retrieve;

#[derive(Parser)]
#[command(name = "fileshadow")]
#[command(about = "Fileshadow - Secure transformative steganographic file hider", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Hide {
        input_file: String,
        file_to_hide_in: String,

        #[arg(long, default_value_t = false)]
        gen_aes: bool,
        #[arg(long)]
        with_aes: Option<String>,
    },
    Retrieve {
        file: String,
        seckey_file: String,
        target_file: Option<String>,

        #[arg(long)]
        with_aes: Option<String>,
    },
}

fn main() -> Result<(), FileShadowError> {
    let cli = Cli::parse();

    let params = CurveParams::random(CurveType::Hybrid);
    let prng_seed = generate_random_seed();

    match cli.command {
        Commands::Hide {
            input_file,
            file_to_hide_in,
            gen_aes,
            with_aes,
        } => {
            let mut aes_key: Option<Vec<u8>> = None;
            let mut aes_nonce: Option<Vec<u8>> = None;

            if gen_aes {
                let key = Aes256Gcm::generate_key(&mut OsRng);
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

                aes_key = Some(key.to_vec());
                aes_nonce = Some(nonce.to_vec());

                println!("AES key and nonce generated.");

                let aes_str = key_and_nonce_to_string(&key, &nonce)?;
                println!("AES key and nonce: {}", aes_str);
                println!(
                    "Use this string to retrieve the file. Store it securely, and seperate from any .seckey files."
                );
            } else if let Some(key_str) = with_aes {
                if !key_str.is_empty() {
                    let (key, nonce) = string_to_key_and_nonce(&key_str)?;
                    aes_key = Some(key);
                    aes_nonce = Some(nonce);
                }
            }

            let hidden_bytelen = hide::hide_file(
                &input_file,
                &file_to_hide_in,
                &params,
                &prng_seed,
                aes_key,
                aes_nonce,
            )?;

            let key = compute_secret_key(hidden_bytelen, &params, &prng_seed);

            let mut i = 0;
            let mut filename = format!(".seckey.{}", i);

            while std::path::Path::new(&filename).exists() {
                i += 1;
                filename = format!(".seckey.{}", i);
            }

            std::fs::write(&filename, key)?;
            println!("Secret key written to {}", filename);
        }
        Commands::Retrieve {
            file,
            seckey_file,
            target_file,
            with_aes,
        } => {
            let secret_key = std::fs::read(seckey_file)?;

            let (bytelen, params, prng_seed) = retrieve_from_secret_key(&secret_key)?;

            let output_path = target_file.unwrap_or_else(|| {
                let mut i = 0;
                let mut filename = format!("out.{}", i);

                while std::path::Path::new(&filename).exists() {
                    i += 1;
                    filename = format!("out.{}", i);
                }

                filename
            });

            let mut aes_key: Option<Vec<u8>> = None;
            let mut aes_nonce: Option<Vec<u8>> = None;

            if let Some(key_str) = with_aes {
                if !key_str.is_empty() {
                    let (key, nonce) = string_to_key_and_nonce(&key_str)?;
                    aes_key = Some(key);
                    aes_nonce = Some(nonce);
                }
            }

            retrieve::retrieve_file(
                &file,
                &output_path,
                &params,
                bytelen,
                &prng_seed,
                aes_key,
                aes_nonce,
            )?;
            println!("File retrieved to {}", output_path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod file_tests {
    use aes_gcm::{AeadCore, KeyInit};
    use std::fs;
    use tempfile::NamedTempFile;

    use crate::{
        crypto::{CurveParams, CurveType, generate_random_seed},
        hide::hide_file,
        retrieve::retrieve_file,
    };

    #[test]
    fn test_hide_and_retrieve_file() {
        let original_data = b"Hello, FileShadow! This is a test.";

        let input_file = NamedTempFile::new().unwrap();
        let cover_file = NamedTempFile::new().unwrap();
        let retrieved_file = NamedTempFile::new().unwrap();

        fs::write(input_file.path(), original_data).unwrap();

        let cover_data = vec![0u8; original_data.len() * 2];
        fs::write(cover_file.path(), cover_data).unwrap();

        let params = CurveParams::random(CurveType::Hybrid);
        let prng_seed = generate_random_seed();

        let hidden_bytelen = hide_file(
            input_file.path().to_str().unwrap(),
            cover_file.path().to_str().unwrap(),
            &params,
            &prng_seed,
            None,
            None,
        )
        .unwrap();

        // Without encryption those should be identical
        assert_eq!(hidden_bytelen, original_data.len());

        retrieve_file(
            cover_file.path().to_str().unwrap(),
            retrieved_file.path().to_str().unwrap(),
            &params,
            hidden_bytelen,
            &prng_seed,
            None,
            None,
        )
        .unwrap();

        let retrieved_data = fs::read(retrieved_file.path()).unwrap();

        assert_eq!(original_data.to_vec(), retrieved_data);
    }

    #[test]
    fn test_hide_and_retrieve_file_with_aes() {
        let original_data = b"Hello, FileShadow! This is a test.";

        let input_file = NamedTempFile::new().unwrap();
        let cover_file = NamedTempFile::new().unwrap();
        let retrieved_file = NamedTempFile::new().unwrap();

        fs::write(input_file.path(), original_data).unwrap();

        let cover_data = vec![0u8; original_data.len() * 3]; // 3 to compensate for AES padding
        fs::write(cover_file.path(), cover_data).unwrap();

        let params = CurveParams::random(CurveType::Hybrid);
        let prng_seed = generate_random_seed();

        let aes_key: Vec<u8> = aes_gcm::Aes256Gcm::generate_key(&mut aes_gcm::aead::OsRng).to_vec();
        let aes_nonce: Vec<u8> =
            aes_gcm::Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng).to_vec();

        let datalen = hide_file(
            input_file.path().to_str().unwrap(),
            cover_file.path().to_str().unwrap(),
            &params,
            &prng_seed,
            Some(aes_key.clone()),
            Some(aes_nonce.clone()),
        )
        .unwrap();

        retrieve_file(
            cover_file.path().to_str().unwrap(),
            retrieved_file.path().to_str().unwrap(),
            &params,
            datalen,
            &prng_seed,
            Some(aes_key),
            Some(aes_nonce),
        )
        .unwrap();

        let retrieved_data = fs::read(retrieved_file.path()).unwrap();

        assert_eq!(original_data.to_vec(), retrieved_data);
    }

    #[test]
    fn test_hide_and_retrieve_empty_file() {
        let original_data: Vec<u8> = vec![];

        let input_file = NamedTempFile::new().unwrap();
        let cover_file = NamedTempFile::new().unwrap();

        fs::write(input_file.path(), original_data.clone()).unwrap();

        let cover_data = vec![0u8; 10];
        fs::write(cover_file.path(), cover_data).unwrap();

        let params = CurveParams::random(CurveType::Hybrid);
        let prng_seed = generate_random_seed();

        let datalen = hide_file(
            input_file.path().to_str().unwrap(),
            cover_file.path().to_str().unwrap(),
            &params,
            &prng_seed,
            None,
            None,
        )
        .unwrap();

        let retrieved_file = NamedTempFile::new().unwrap();
        retrieve_file(
            cover_file.path().to_str().unwrap(),
            retrieved_file.path().to_str().unwrap(),
            &params,
            datalen,
            &prng_seed,
            None,
            None,
        )
        .unwrap();

        let retrieved_data = fs::read(retrieved_file.path()).unwrap();

        assert_eq!(original_data, retrieved_data);
    }
}
