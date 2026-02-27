use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// Mine a proof-of-work nonce for the given body using all available cores.
/// Returns the 8-byte nonce as a hex string.
pub fn mine(body: &[u8], difficulty: u32) -> String {
    if difficulty == 0 {
        return "0000000000000000".to_string();
    }

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(AtomicU64::new(0));

    std::thread::scope(|s| {
        for thread_id in 0..threads {
            let found = Arc::clone(&found);
            let result = Arc::clone(&result);
            s.spawn(move || {
                let mut nonce = thread_id as u64;
                let step = threads as u64;
                while !found.load(Ordering::Relaxed) {
                    let nonce_bytes = nonce.to_be_bytes();
                    let mut hasher = Sha256::new();
                    hasher.update(nonce_bytes);
                    hasher.update(body);
                    let hash = hasher.finalize();
                    if leading_zero_bits(&hash) >= difficulty {
                        result.store(nonce, Ordering::Relaxed);
                        found.store(true, Ordering::Relaxed);
                        return;
                    }
                    nonce += step;
                }
            });
        }
    });

    hex_encode(&result.load(Ordering::Relaxed).to_be_bytes())
}

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

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0xf) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mine_and_verify() {
        let body = b"hello world";
        let difficulty = 16;
        let nonce_hex = mine(body, difficulty);

        assert_eq!(nonce_hex.len(), 16);

        // Verify: decode nonce and check hash
        let mut nonce = [0u8; 8];
        for (i, chunk) in nonce_hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0]);
            let lo = hex_val(chunk[1]);
            nonce[i] = (hi << 4) | lo;
        }

        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(body);
        let hash = hasher.finalize();
        assert!(leading_zero_bits(&hash) >= difficulty);
    }

    fn hex_val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }

    #[test]
    fn test_zero_difficulty() {
        let nonce = mine(b"anything", 0);
        assert_eq!(nonce, "0000000000000000");
    }
}
