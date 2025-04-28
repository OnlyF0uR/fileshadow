use std::fs;

use crate::{
    crypto::{CurveParams, apply_hiding, encrypt_bytes, generate_shuffled_positions},
    error::FileShadowError,
};

pub fn hide_file(
    input_file: &str,
    cover_file: &str,
    params: &CurveParams,
    prng_seed: &[u8],
    aes_key: Option<Vec<u8>>,
    aes_iv: Option<Vec<u8>>,
) -> Result<usize, FileShadowError> {
    let mut input_data = fs::read(input_file)?;

    if aes_key.is_some() && aes_iv.is_some() {
        // Encrypt the input data if AES key and IV are provided
        input_data = encrypt_bytes(&input_data, &aes_key.unwrap(), &aes_iv.unwrap())?;
    }

    let mut cover_data = fs::read(cover_file)?;
    if cover_data.len() < input_data.len() * 2 {
        return Err(FileShadowError::CoverFileTooSmall);
    }

    // Generate shuffled positions based on the curve parameters and cover file length
    let shuffled_positions = generate_shuffled_positions(params, cover_data.len(), prng_seed)?;

    // Map each byte from the input file to a shuffled position in the cover file
    for (i, &byte) in input_data.iter().enumerate() {
        let pos = shuffled_positions[i]; // Get the position from the shuffled positions
        let factor = params.generate_factor(i); // Generate the hiding factor for the byte
        let modified_byte = apply_hiding(byte, factor); // Apply the hiding mechanism
        cover_data[pos] = modified_byte; // Modify the cover file data at the shuffled position
    }

    fs::write(cover_file, cover_data)?;

    // Delete the original input file
    fs::remove_file(input_file)?;

    Ok(input_data.len())
}
