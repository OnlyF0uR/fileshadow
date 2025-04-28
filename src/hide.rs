use std::fs;

use crate::{
    crypto::{CurveParams, apply_hiding, generate_shuffled_positions},
    error::FileShadowError,
};

pub fn hide_file(
    input_file: &str,
    cover_file: &str,
    params: &CurveParams,
    prng_seed: &[u8],
) -> Result<usize, FileShadowError> {
    let input_data = fs::read(input_file)?;
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
    Ok(input_data.len())
}
