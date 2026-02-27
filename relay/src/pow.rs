//! Proof-of-work and replay protection for incoming messages.

use std::collections::HashSet;
use std::sync::Mutex;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};

pub use resolver::{POW_HEADER, DEFAULT_DIFFICULTY};

/// Max entries in the replay cache before clearing.
const MAX_SEEN: usize = 100_000;

/// Proof-of-work verifier and replay cache.
pub struct PowGuard {
    difficulty: u32,
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl Default for PowGuard {
    fn default() -> Self {
        Self::new(DEFAULT_DIFFICULTY)
    }
}

impl PowGuard {
    pub fn new(difficulty: u32) -> Self {
        Self {
            difficulty,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Validate proof-of-work and reject replays.
    pub fn check(
        &self,
        headers: &HeaderMap,
        body: &Bytes,
    ) -> Result<(), (StatusCode, &'static str)> {
        if self.difficulty > 0 {
            let header = headers
                .get(POW_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or((StatusCode::BAD_REQUEST, "missing X-Pow header"))?;

            let nonce =
                decode_pow_nonce(header).ok_or((StatusCode::BAD_REQUEST, "invalid X-Pow nonce"))?;

            if !verify_pow(&nonce, body, self.difficulty) {
                return Err((StatusCode::FORBIDDEN, "insufficient proof of work"));
            }
        }

        // Replay check (keyed on body hash)
        let hash: [u8; 32] = Sha256::digest(body).into();
        {
            let mut seen = self.seen.lock().unwrap();
            if !seen.insert(hash) {
                return Err((StatusCode::BAD_REQUEST, "duplicate message"));
            }
            if seen.len() > MAX_SEEN {
                seen.clear();
                seen.insert(hash);
            }
        }

        Ok(())
    }
}

/// Verify proof-of-work: SHA256(nonce || body) must have `difficulty` leading zero bits.
fn verify_pow(nonce: &[u8; 8], body: &[u8], difficulty: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(body);
    let hash = hasher.finalize();
    leading_zero_bits(&hash) >= difficulty
}

/// Count the number of leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut bits = 0;
    for &byte in data {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Decode a hex-encoded 8-byte nonce from the X-Pow header.
fn decode_pow_nonce(header: &str) -> Option<[u8; 8]> {
    let header = header.trim();
    if header.len() != 16 {
        return None;
    }
    let mut nonce = [0u8; 8];
    for (i, chunk) in header.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        nonce[i] = (hi << 4) | lo;
    }
    Some(nonce)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
