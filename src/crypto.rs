use crate::error::FileShadowError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use blake3::Hasher;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

/// Defines the type of curve algorithm used for file hiding
#[derive(Debug, Clone)]
pub enum CurveType {
    /// Hybrid approach combining sinusoidal, logistic map, and hash-based noise
    Hybrid,
    // Future curve types can be added here
}

/// Parameters that control the file hiding behavior
#[derive(Debug, Clone)]
pub struct CurveParams {
    /// Type of curve algorithm to use
    pub curve_type: CurveType,
    /// Seed value specifying HOW data is transformed
    pub curve_seed: u64,
    /// Amplitude of the sinusoidal component
    pub sin_amplitude: f32,
    /// Frequency of the sinusoidal component
    pub sin_frequency: f32,
    /// Phase shift of the sinusoidal component
    pub sin_phase: f32,
    /// Parameter for the logistic map (typical values: 3.57 to 4.0)
    pub logistic_r: f32,
    /// Weight of the hash noise contribution (0.0 to 1.0)
    pub hash_weight: f32,
}

impl CurveParams {
    // Cache for logistic map calculations
    thread_local! {
        static LOGISTIC_CACHE: std::cell::RefCell<HashMap<(u64, usize), f32>> = std::cell::RefCell::new(HashMap::new());
    }

    /// Creates a new instance of CurveParams with default values
    ///
    /// This function initializes the parameters with random values for the sinusoidal and logistic components.
    /// It is used for testing and generating unique hiding patterns.
    /// Returns a CurveParams instance with randomized parameters.
    pub fn random(curve_type: CurveType) -> Self {
        // Generate random parameters for the curve
        let mut rng = ChaCha20Rng::from_os_rng();
        let curve_seed: u64 = rng.random::<u64>();
        let sin_amplitude = rng.random_range(0.5..5.0);
        let sin_frequency = rng.random_range(0.1..2.0);
        let sin_phase = rng.random_range(0.0..std::f32::consts::PI * 2.0);
        let logistic_r = rng.random_range(3.57..4.0); // Typical range for chaos
        let hash_weight = rng.random_range(0.1..0.9);

        Self {
            curve_type,
            curve_seed,
            sin_amplitude,
            sin_frequency,
            sin_phase,
            logistic_r,
            hash_weight,
        }
    }

    /// Generates a transformation factor based on position and curve parameters
    ///
    /// This factor is used to transform bytes during the hiding process.
    /// Returns a value normalized to the range [0.8, 1.2]
    pub fn generate_factor(&self, position: usize) -> f32 {
        match self.curve_type {
            CurveType::Hybrid => {
                let x = position as f32;

                // 1. Sinusoidal part
                let sin_part = self.sin_amplitude * (self.sin_frequency * x + self.sin_phase).sin();

                // 2. Logistic map part - using cached values for performance
                let logistic_part = self.get_logistic_value(position);

                // 3. Hash noise part
                let hash_noise = {
                    let mut hasher = Hasher::new();
                    hasher.update(&self.curve_seed.to_le_bytes());
                    hasher.update(&position.to_le_bytes());
                    let hash = hasher.finalize();
                    let bytes = hash.as_bytes();
                    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    (val as f32) / (u32::MAX as f32) // normalize to 0.0 - 1.0
                };

                // 4. Combine parts
                let combined = sin_part + logistic_part + (self.hash_weight * hash_noise);

                // 5. Normalize result to [0.8, 1.2] range for byte multiplication
                // This range ensures meaningful but not extreme transformations
                let normalized = 0.8 + (combined.fract() * 0.4);

                normalized
            }
        }
    }

    // Get logistic map value for a position, using caching for performance
    fn get_logistic_value(&self, position: usize) -> f32 {
        // Check if we already calculated this value
        let cache_key = (self.curve_seed, position);

        let cached_value = Self::LOGISTIC_CACHE.with(|cache| {
            let borrowed_cache = cache.borrow();
            borrowed_cache.get(&cache_key).cloned()
        });

        if let Some(value) = cached_value {
            return value;
        }

        // Calculate the value if not cached
        let mut logistic_x = self.seed_to_float();
        for _ in 0..position {
            logistic_x = self.logistic_next(logistic_x);
        }

        let result = logistic_x;

        // Cache the result
        Self::LOGISTIC_CACHE.with(|cache| {
            let mut borrowed_cache = cache.borrow_mut();
            borrowed_cache.insert(cache_key, result);
        });

        result
    }

    /// Computes the next value in the logistic map sequence
    fn logistic_next(&self, x: f32) -> f32 {
        self.logistic_r * x * (1.0 - x)
    }

    /// Converts the seed value to a float in the range [0,1]
    fn seed_to_float(&self) -> f32 {
        let max = u64::MAX as f32;
        (self.curve_seed as f32) / max
    }
}

/// Applies the hiding mechanism to a byte using the calculated factor
///
/// This operation is reversible - applying it twice with the same factor
/// returns the original byte.
///
/// # Security Note
/// This is a simple XOR transformation and is not cryptographically secure on its own.
/// The security of the system relies on the entire algorithm including position shuffling.
pub fn apply_hiding(original: u8, factor: f32) -> u8 {
    let factor_byte = (factor * 255.0).clamp(0.0, 255.0) as u8;
    original ^ factor_byte
}

/// Generates a deterministically shuffled sequence of positions based on parameters
///
/// Used to determine where bytes will be placed in the cover file.
/// Returns ordered positions in the range [0, cover_len)
pub fn generate_shuffled_positions(
    params: &CurveParams,
    cover_len: usize,
    prng_seed: &[u8],
) -> Result<Vec<usize>, FileShadowError> {
    // Handle potential overflow for very large files
    if cover_len > usize::MAX / 2 {
        return Err(FileShadowError::FileTooLarge);
    }

    let mut positions: Vec<usize> = (0..cover_len).collect();

    // Extend the seed to 32 bytes by repeating the seed value
    let mut extended_seed = Vec::with_capacity(32);
    extended_seed.extend_from_slice(&params.curve_seed.to_le_bytes()); // Add the 8-byte seed
    while extended_seed.len() < 32 {
        extended_seed.push(0); // Pad with zeros
    }

    // Convert extended_seed to a fixed slice of exactly 32 bytes
    let extended_seed: [u8; 32] = vec_to_array_32(extended_seed)?;

    // Generate a PRNG seed using Blake3 keyed hash with the 32-byte key
    let prng_seed = blake3::keyed_hash(&extended_seed, prng_seed)
        .as_bytes()
        .clone();

    let mut rng = ChaCha20Rng::from_seed(prng_seed[..32].try_into().unwrap());

    // Shuffle positions deterministically using the PRNG
    positions.shuffle(&mut rng);

    Ok(positions)
}

/// Generates a random 32-byte seed using ChaCha20RNG
///
/// This function is used for generating random seeds for the PRNG.
/// Used for generating seeds that control WHERE the transformed data
/// is placed.
pub fn generate_random_seed() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_os_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
}

/// Computes a secret key based on the byte length, curve parameters, and PRNG seed
///
/// This key is used for encoding and decoding the hidden data.
/// It includes the byte length, curve parameters, and PRNG seed.
/// Returns a vector of bytes representing the secret key.
/// The byte length is serialized as 8 bytes (usize).
/// The CurveParams fields are serialized as follows:
/// - curve_seed: 8 bytes (u64)
/// - sin_amplitude: 4 bytes (f32)
/// - sin_frequency: 4 bytes (f32)
/// - sin_phase: 4 bytes (f32)
/// - logistic_r: 4 bytes (f32)
/// - hash_weight: 4 bytes (f32)
/// The PRNG seed is appended as 32 bytes.
pub fn compute_secret_key(byte_len: usize, params: &CurveParams, prng_seed: &[u8]) -> Vec<u8> {
    let mut secret_key = Vec::new();

    // Serialize the byte_len (usize) into bytes
    secret_key.extend_from_slice(&byte_len.to_le_bytes()); // Convert to little-endian bytes

    // Serialize CurveParams:
    // Assuming the CurveParams struct contains these fields:
    secret_key.extend_from_slice(&params.curve_seed.to_le_bytes());
    secret_key.extend_from_slice(&params.sin_amplitude.to_le_bytes());
    secret_key.extend_from_slice(&params.sin_frequency.to_le_bytes());
    secret_key.extend_from_slice(&params.sin_phase.to_le_bytes());
    secret_key.extend_from_slice(&params.logistic_r.to_le_bytes());
    secret_key.extend_from_slice(&params.hash_weight.to_le_bytes());

    // Append the prng_seed (32 bytes)
    secret_key.extend_from_slice(prng_seed);

    secret_key
}

/// Retrieves the byte length, curve parameters, and PRNG seed from the secret key
///
/// This function decodes the secret key back into its components.
/// It extracts the byte length, curve parameters, and PRNG seed from the byte array.
/// Returns a tuple containing:
///  - byte_len: usize
///  - params: CurveParams
///  - prng_seed: Vec<u8> (32 bytes)
pub fn retrieve_from_secret_key(
    secret_key: &[u8],
) -> Result<(usize, CurveParams, Vec<u8>), FileShadowError> {
    let mut idx = 0;

    // Retrieve the byte_len (usize)
    let byte_len = usize::from_le_bytes(secret_key[idx..idx + 8].try_into()?);
    idx += 8;

    // Retrieve CurveParams fields:
    let curve_seed = u64::from_le_bytes(secret_key[idx..idx + 8].try_into()?);
    idx += 8;
    let sin_amplitude = f32::from_le_bytes(secret_key[idx..idx + 4].try_into()?);
    idx += 4;
    let sin_frequency = f32::from_le_bytes(secret_key[idx..idx + 4].try_into()?);
    idx += 4;
    let sin_phase = f32::from_le_bytes(secret_key[idx..idx + 4].try_into()?);
    idx += 4;
    let logistic_r = f32::from_le_bytes(secret_key[idx..idx + 4].try_into()?);
    idx += 4;
    let hash_weight = f32::from_le_bytes(secret_key[idx..idx + 4].try_into()?);
    idx += 4;

    // Create the CurveParams object
    let params = CurveParams {
        curve_type: CurveType::Hybrid, // Assuming Hybrid for now
        curve_seed,
        sin_amplitude,
        sin_frequency,
        sin_phase,
        logistic_r,
        hash_weight,
    };

    // Retrieve the prng_seed (32 bytes)
    let prng_seed = secret_key[idx..idx + 32].to_vec();

    Ok((byte_len, params, prng_seed))
}

/// Encrypts the input bytes using AES-GCM with the provided key and nonce
///
/// This function takes the input data, key, and nonce as parameters,
/// and returns the encrypted data as a vector of bytes.
pub fn encrypt_bytes(input: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, FileShadowError> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(FileShadowError::InvalidEncryptionKeyLength(32, key.len()));
    }

    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce);

    let encrypted_data = cipher.encrypt(&nonce, input)?;
    Ok(encrypted_data)
}

/// Decrypts the input bytes using AES-GCM with the provided key and nonce
///
/// This function takes the encrypted data, key, and nonce as parameters,
/// and returns the decrypted data as a vector of bytes.
pub fn decrypt_bytes(
    encrypted_data: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, FileShadowError> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(FileShadowError::InvalidEncryptionKeyLength(32, key.len()));
    }

    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce: &[u8; 12] = nonce.try_into()?;

    let nonce = Nonce::from_slice(nonce); // 12-byte nonce
    let decrypted_data = cipher.decrypt(nonce, encrypted_data)?;
    Ok(decrypted_data)
}

/// Converts the key and nonce into a hex string representation
///
/// This function takes the key and nonce as byte slices,
/// and returns a hex-encoded string.
/// The key should be 32 bytes and the nonce should be 12 bytes.
pub fn key_and_nonce_to_string(key: &[u8], nonce: &[u8]) -> Result<String, FileShadowError> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(FileShadowError::InvalidEncryptionKeyLength(32, key.len()));
    }

    // add the bytes together
    let mut combined = Vec::new();
    combined.extend_from_slice(key);
    combined.extend_from_slice(nonce);

    let hex_str = hex::encode(&combined);
    Ok(hex_str)
}

/// Converts a hex string representation of key and nonce back into byte vectors
///
/// This function takes a hex string and decodes it into two byte vectors:
/// - key (32 bytes)
/// - nonce (12 bytes)
/// Returns a tuple containing the key and nonce as byte vectors.
pub fn string_to_key_and_nonce(hex_str: &str) -> Result<(Vec<u8>, Vec<u8>), FileShadowError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 44 {
        return Err(FileShadowError::InvalidSeedSize);
    }

    let key = bytes[0..32].to_vec(); // First 32 bytes for the key
    let nonce = bytes[32..44].to_vec(); // Next 12 bytes for the nonce

    Ok((key, nonce))
}

/// Convert Vec<u8> to a fixed-size [u8; 32] array
///
/// # Errors
/// Returns an error if the vector's length is not exactly 32 bytes
fn vec_to_array_32(vec: Vec<u8>) -> Result<[u8; 32], FileShadowError> {
    if vec.len() != 32 {
        return Err(FileShadowError::IncongruentCastLength(32, vec.len()));
    }

    let array: [u8; 32] = vec.as_slice().try_into()?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_hiding() {
        let original_byte: u8 = 123;
        let factor: f32 = 0.5;

        let result = apply_hiding(original_byte, factor);
        assert_ne!(original_byte, result);

        // Applying XOR twice should give the original byte back
        let reverse_result = apply_hiding(result, factor);
        assert_eq!(original_byte, reverse_result);
    }

    #[test]
    fn test_generate_shuffled_positions() {
        let params = CurveParams {
            curve_type: CurveType::Hybrid,
            curve_seed: 12345,
            sin_amplitude: 1.0,
            sin_frequency: 1.0,
            sin_phase: 0.0,
            logistic_r: 3.9999,
            hash_weight: 1.0,
        };

        let prng_seed = b"test_shuffle";

        let cover_len = 10;
        let positions = generate_shuffled_positions(&params, cover_len, prng_seed).unwrap();

        // Check that the generated positions are within the bounds
        for &pos in &positions {
            assert!(pos < cover_len);
        }

        // Ensure that positions are shuffled (not in order)
        assert_ne!(positions, (0..cover_len).collect::<Vec<usize>>());
    }

    #[test]
    fn test_deterministic_output() {
        let params1 = CurveParams {
            curve_type: CurveType::Hybrid,
            curve_seed: 42,
            sin_amplitude: 1.0,
            sin_frequency: 1.0,
            sin_phase: 0.0,
            logistic_r: 3.9,
            hash_weight: 0.5,
        };

        let params2 = params1.clone();

        // Generate factors for the same positions
        let factor1_pos10 = params1.generate_factor(10);
        let factor2_pos10 = params2.generate_factor(10);

        // They should be identical since parameters are the same
        assert_eq!(factor1_pos10, factor2_pos10);

        // Test shuffled positions are also deterministic
        let prng_seed = b"test_deterministic";
        let positions1 = generate_shuffled_positions(&params1, 100, prng_seed).unwrap();
        let positions2 = generate_shuffled_positions(&params2, 100, prng_seed).unwrap();

        assert_eq!(positions1, positions2);
    }

    #[test]
    fn test_edge_cases() {
        let params = CurveParams {
            curve_type: CurveType::Hybrid,
            curve_seed: 12345,
            sin_amplitude: 1.0,
            sin_frequency: 1.0,
            sin_phase: 0.0,
            logistic_r: 3.9999,
            hash_weight: 1.0,
        };

        // Test large position values
        let factor_large = params.generate_factor(1_000_000);
        assert!(factor_large >= 0.8 && factor_large <= 1.2);

        // Test extreme parameter values
        let extreme_params = CurveParams {
            curve_type: CurveType::Hybrid,
            curve_seed: u64::MAX,
            sin_amplitude: 100.0,  // Very high amplitude
            sin_frequency: 0.0001, // Very low frequency
            sin_phase: 1000.0,     // High phase
            logistic_r: 4.0,       // Maximum chaos
            hash_weight: 10.0,     // High weight
        };

        let extreme_factor = extreme_params.generate_factor(50);
        // Should still be normalized properly
        assert!(extreme_factor >= 0.8 && extreme_factor <= 1.2);
    }

    #[test]
    fn test_vec_to_array_32() {
        let vec = vec![0u8; 32];
        let result = vec_to_array_32(vec.clone()).unwrap();
        assert_eq!(result, [0u8; 32]);

        // Test with incorrect length
        let short_vec = vec![0u8; 31];
        assert!(vec_to_array_32(short_vec).is_err());

        // Test with too long vector
        let long_vec = vec![0u8; 33];
        assert!(vec_to_array_32(long_vec).is_err());
    }

    #[test]
    fn encode_and_decode_keys() {
        let parmas = CurveParams::random(CurveType::Hybrid);
        let prng_seed = generate_random_seed();

        let byte_len = 1000; // Example length

        let secret_key = compute_secret_key(byte_len, &parmas, &prng_seed);
        let (decoded_byte_len, decoded_params, decoded_prng_seed) =
            retrieve_from_secret_key(&secret_key).unwrap();

        assert_eq!(byte_len, decoded_byte_len);
        assert_eq!(parmas.curve_seed, decoded_params.curve_seed);
        assert_eq!(parmas.sin_amplitude, decoded_params.sin_amplitude);
        assert_eq!(parmas.sin_frequency, decoded_params.sin_frequency);
        assert_eq!(parmas.sin_phase, decoded_params.sin_phase);
        assert_eq!(parmas.logistic_r, decoded_params.logistic_r);
        assert_eq!(parmas.hash_weight, decoded_params.hash_weight);
        assert_eq!(prng_seed, decoded_prng_seed.as_slice());
    }

    #[test]
    fn test_key_and_nonce_conversion() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];

        let hex_str = key_and_nonce_to_string(&key, &nonce).unwrap();
        let (decoded_key, decoded_nonce) = string_to_key_and_nonce(&hex_str).unwrap();

        assert_eq!(key.to_vec(), decoded_key);
        assert_eq!(nonce.to_vec(), decoded_nonce);
    }

    #[test]
    fn test_invalid_key_and_nonce_conversion() {
        let invalid_hex_str = "invalid_hex_string";
        assert!(string_to_key_and_nonce(invalid_hex_str).is_err());

        let key = [1u8; 32];
        let nonce = [2u8; 12];

        let hex_str = key_and_nonce_to_string(&key, &nonce).unwrap();
        let (decoded_key, decoded_nonce) = string_to_key_and_nonce(&hex_str).unwrap();

        assert_eq!(key.to_vec(), decoded_key);
        assert_eq!(nonce.to_vec(), decoded_nonce);
    }

    #[test]
    fn test_invalid_key_and_nonce_length() {
        let key = [1u8; 31]; // Invalid length
        let nonce = [2u8; 12];

        assert!(key_and_nonce_to_string(&key, &nonce).is_err());

        let key = [1u8; 32];
        let nonce = [2u8; 13]; // Invalid length

        assert!(key_and_nonce_to_string(&key, &nonce).is_err());
    }

    #[test]
    fn test_invalid_encryption_key_length() {
        let key = [1u8; 31]; // Invalid length
        let nonce = [2u8; 12];

        assert!(encrypt_bytes(&[0], &key, &nonce).is_err());
        assert!(decrypt_bytes(&[0], &key, &nonce).is_err());
    }

    #[test]
    fn test_encryption_decryption() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let data = b"Hello, World!";

        let encrypted_data = encrypt_bytes(data, &key, &nonce).unwrap();
        let decrypted_data = decrypt_bytes(&encrypted_data, &key, &nonce).unwrap();

        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_invalid_encryption_decryption() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let data = b"Hello, World!";

        // Test with invalid key length
        let invalid_key = [1u8; 31]; // Invalid length
        assert!(encrypt_bytes(data, &invalid_key, &nonce).is_err());
        assert!(decrypt_bytes(data, &invalid_key, &nonce).is_err());

        // Test with invalid nonce length
        let invalid_nonce = [2u8; 11]; // Invalid length
        assert!(encrypt_bytes(data, &key, &invalid_nonce).is_err());
        assert!(decrypt_bytes(data, &key, &invalid_nonce).is_err());
    }
}
