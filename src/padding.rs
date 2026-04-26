use rand::RngCore;

/// Errors from [`unpad`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PadError {
    /// Input is shorter than the 4-byte length prefix.
    #[error("padded input too short ({0} bytes, need >= 4)")]
    TooShort(usize),
    /// Length prefix declares more bytes than the input contains. Indicates
    /// either tampering of an AEAD-valid plaintext (bogus prefix) or a
    /// non-padded blob misrouted into a padded path.
    #[error("declared payload length {declared} exceeds available {available} bytes")]
    LengthOverrun { declared: usize, available: usize },
}

/// Remove padding: extract original data using the 4-byte BE length prefix.
///
/// Returns `Err` if the prefix is missing or declares more bytes than the
/// input contains. Callers that legitimately accept un-padded legacy V0 input
/// must handle the error explicitly (e.g. `unpad(d).unwrap_or(d)`); see
/// `client::decrypt_link_grant` for the canonical legacy fallback.
pub fn unpad(data: &[u8]) -> Result<&[u8], PadError> {
    if data.len() < 4 {
        return Err(PadError::TooShort(data.len()));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let available = data.len() - 4;
    if len > available {
        return Err(PadError::LengthOverrun {
            declared: len,
            available,
        });
    }
    Ok(&data[4..4 + len])
}

/// Calculate padded bucket size for a given plaintext length.
/// Buckets: <=1KB -> 1KB, <=16KB -> power-of-2, <=1MB -> 64KB boundary,
/// <=64MB -> 1MB boundary, >64MB -> 8MB boundary.
pub fn padded_size(actual: usize) -> usize {
    let total = 4 + actual;
    if total <= 1024 {
        return 1024;
    }
    if total <= 16384 {
        let mut s = 1024;
        while s < total {
            s *= 2;
        }
        return s;
    }
    if total <= 1_048_576 {
        return total.div_ceil(65536) * 65536;
    }
    if total <= 67_108_864 {
        return total.div_ceil(1_048_576) * 1_048_576;
    }
    total.div_ceil(8_388_608) * 8_388_608
}

/// Pad plaintext with 4-byte BE length prefix + random padding to bucket size.
pub fn pad_plaintext(data: &[u8]) -> Vec<u8> {
    let target = padded_size(data.len());
    let mut result = vec![0u8; target];
    let len = data.len() as u32;
    result[..4].copy_from_slice(&len.to_be_bytes());
    result[4..4 + data.len()].copy_from_slice(data);
    if target > 4 + data.len() {
        rand::rngs::OsRng.fill_bytes(&mut result[4 + data.len()..]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_size_buckets() {
        // <= 1KB
        assert_eq!(padded_size(0), 1024);
        assert_eq!(padded_size(1), 1024);
        assert_eq!(padded_size(1020), 1024); // 4 + 1020 = 1024
                                             // Power-of-2 range
        assert_eq!(padded_size(1021), 2048); // 4 + 1021 = 1025 > 1024
        assert_eq!(padded_size(2044), 2048);
        assert_eq!(padded_size(2045), 4096);
        assert_eq!(padded_size(16380), 16384);
        // 64KB boundary range
        assert_eq!(padded_size(16381), 65536);
        assert_eq!(padded_size(65532), 65536); // 4 + 65532 = 65536
        assert_eq!(padded_size(65533), 131072);
        assert_eq!(padded_size(100_000), 131072);
        // 1MB boundary range
        assert_eq!(padded_size(1_048_572), 1_048_576); // 4 + 1_048_572 = 1_048_576
        assert_eq!(padded_size(1_048_573), 2_097_152); // crosses into 1MB boundary range
                                                       // 8MB boundary range
        assert_eq!(padded_size(67_108_861), 75_497_472);
    }

    #[test]
    fn pad_unpad_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"x",
            b"hello world",
            &vec![0xAB; 1020],    // exactly fills 1KB bucket
            &vec![0xCD; 5000],    // mid-range
            &vec![0xEF; 100_000], // larger
        ];
        for data in cases {
            let padded = pad_plaintext(data);
            assert_eq!(padded.len(), padded_size(data.len()));
            let recovered = unpad(&padded).expect("pad/unpad roundtrip");
            assert_eq!(recovered, *data);
        }
    }

    #[test]
    fn pad_output_length_matches_padded_size() {
        for size in [0, 1, 100, 1020, 1021, 5000, 16380, 16381, 100_000] {
            let data = vec![0u8; size];
            let padded = pad_plaintext(&data);
            assert_eq!(padded.len(), padded_size(size));
        }
    }

    #[test]
    fn unpad_corrupted_prefix_errors() {
        // Length prefix says more data than available — return PadError, do
        // NOT silently hand back the raw input.
        let data = [0, 0, 0, 100, 1, 2, 3];
        assert_eq!(
            unpad(&data),
            Err(PadError::LengthOverrun {
                declared: 100,
                available: 3,
            })
        );
    }

    #[test]
    fn unpad_too_short_errors() {
        assert_eq!(unpad(&[1, 2, 3]), Err(PadError::TooShort(3)));
        assert_eq!(unpad(&[]), Err(PadError::TooShort(0)));
    }

    #[test]
    fn unpad_zero_length_prefix() {
        // Edge case: prefix says 0 bytes — return empty slice, not error.
        let data = [0, 0, 0, 0, 0xAA, 0xBB];
        assert_eq!(unpad(&data), Ok(&[] as &[u8]));
    }
}
