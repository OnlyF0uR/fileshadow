#[derive(Debug)]
pub enum FileShadowError {
    IoError(std::io::Error),
    CoverFileTooSmall,
    IncongruentCastLength(usize, usize),
    ConversionError(std::array::TryFromSliceError),
    InvalidSeedSize,
    FileTooLarge,
    InvalidEncryptionKeyLength(usize, usize),
    EncryptionError(aes_gcm::Error),
    Utf8Error(std::string::FromUtf8Error),
    HexDecodingError(hex::FromHexError),
}

impl std::fmt::Display for FileShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileShadowError::IoError(err) => err.fmt(f),
            FileShadowError::CoverFileTooSmall => write!(
                f,
                "File is too small to hide data. Needs to be at least double the size of the input file."
            ),
            FileShadowError::IncongruentCastLength(expected, actual) => {
                write!(
                    f,
                    "Incongruent cast length. Expected: {}, Actual: {}",
                    expected, actual
                )
            }
            FileShadowError::ConversionError(err) => err.fmt(f),
            FileShadowError::InvalidSeedSize => write!(
                f,
                "Invalid seed size. Expected 32 bytes, got different size."
            ),
            FileShadowError::FileTooLarge => {
                write!(f, "File is too large. The maximum size is 2^32 bytes.")
            }
            FileShadowError::InvalidEncryptionKeyLength(expected, actual) => {
                write!(
                    f,
                    "Invalid encryption key length. Expected: {}, Actual: {}",
                    expected, actual
                )
            }
            FileShadowError::EncryptionError(err) => err.fmt(f),
            FileShadowError::Utf8Error(err) => err.fmt(f),
            FileShadowError::HexDecodingError(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for FileShadowError {}

impl From<std::io::Error> for FileShadowError {
    fn from(err: std::io::Error) -> Self {
        FileShadowError::IoError(err)
    }
}

impl From<std::array::TryFromSliceError> for FileShadowError {
    fn from(e: std::array::TryFromSliceError) -> Self {
        FileShadowError::ConversionError(e)
    }
}

impl From<aes_gcm::Error> for FileShadowError {
    fn from(err: aes_gcm::Error) -> Self {
        FileShadowError::EncryptionError(err)
    }
}

impl From<std::string::FromUtf8Error> for FileShadowError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        FileShadowError::Utf8Error(err)
    }
}

impl From<hex::FromHexError> for FileShadowError {
    fn from(err: hex::FromHexError) -> Self {
        FileShadowError::HexDecodingError(err)
    }
}
