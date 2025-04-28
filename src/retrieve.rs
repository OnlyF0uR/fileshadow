use crate::{
    crypto::{CurveParams, apply_hiding, decrypt_bytes, generate_shuffled_positions},
    error::FileShadowError,
};
use std::fs;

pub fn retrieve_file(
    file: &str,
    output_file: &str,
    params: &CurveParams,
    data_length: usize,
    prng_seed: &[u8],
    aes_key: Option<Vec<u8>>,
    aes_iv: Option<Vec<u8>>,
) -> Result<(), FileShadowError> {
    // Read the cover file bytes
    let cover_data = fs::read(file)?;

    // Generate shuffled positions for the cover file based on the params
    let shuffled_positions = generate_shuffled_positions(params, cover_data.len(), prng_seed)?;

    // Initialize a vector to hold the retrieved bytes
    let mut retrieved_data = Vec::with_capacity(data_length);

    // Retrieve the hidden data by applying the inverse transformation (XOR)
    for i in 0..data_length {
        if i >= shuffled_positions.len() {
            break;
        }

        let pos = shuffled_positions[i]; // Get the position where the byte was hidden
        let factor = params.generate_factor(i); // Generate the same factor used during hiding
        let original_byte = apply_hiding(cover_data[pos], factor); // Apply XOR to get the original byte
        retrieved_data.push(original_byte);
    }

    if aes_key.is_some() && aes_iv.is_some() {
        // Decrypt the retrieved data if AES key and IV are provided
        retrieved_data = decrypt_bytes(&retrieved_data, &aes_key.unwrap(), &aes_iv.unwrap())?;
    }

    // Write the retrieved data to the specified output file
    fs::write(output_file, retrieved_data)?;
    Ok(())
}
