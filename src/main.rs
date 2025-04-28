use clap::{Parser, Subcommand};
use crypto::{
    CurveParams, CurveType, compute_secret_key, generate_random_seed, retrieve_from_secret_key,
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
    },
    Retrieve {
        file: String,
        seckey_file: String,
        target_file: Option<String>,
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
        } => {
            let hidden_bytelen =
                hide::hide_file(&input_file, &file_to_hide_in, &params, &prng_seed)?;

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

            retrieve::retrieve_file(&file, &output_path, &params, bytelen, &prng_seed)?;
            println!("File retrieved to {}", output_path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod file_tests {
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
        let data_length = original_data.len();

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
        )
        .unwrap();

        assert_eq!(hidden_bytelen, data_length);

        retrieve_file(
            cover_file.path().to_str().unwrap(),
            retrieved_file.path().to_str().unwrap(),
            &params,
            data_length,
            &prng_seed,
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

        hide_file(
            input_file.path().to_str().unwrap(),
            cover_file.path().to_str().unwrap(),
            &params,
            &prng_seed,
        )
        .unwrap();

        let retrieved_file = NamedTempFile::new().unwrap();
        retrieve_file(
            cover_file.path().to_str().unwrap(),
            retrieved_file.path().to_str().unwrap(),
            &params,
            original_data.len(),
            &prng_seed,
        )
        .unwrap();

        let retrieved_data = fs::read(retrieved_file.path()).unwrap();

        assert_eq!(original_data, retrieved_data);
    }
}
