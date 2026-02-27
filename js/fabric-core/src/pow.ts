const DEFAULT_DIFFICULTY = 36;

/** Count leading zero bits in a Uint8Array. */
function leadingZeroBits(data: Uint8Array): number {
  let bits = 0;
  for (const byte of data) {
    if (byte === 0) {
      bits += 8;
    } else {
      bits += Math.clz32(byte) - 24; // clz32 counts for 32-bit, byte is 8-bit
      break;
    }
  }
  return bits;
}

/** Write a 64-bit big-endian unsigned integer into a Uint8Array. */
function writeU64BE(buf: Uint8Array, value: bigint): void {
  const view = new DataView(buf.buffer, buf.byteOffset, 8);
  view.setBigUint64(0, value, false);
}

/**
 * Mine a proof-of-work nonce for the given body.
 * Returns the 8-byte nonce as a 16-char hex string.
 * Single-threaded; runs synchronously using the provided SubtleCrypto.
 */
export async function mine(
  body: Uint8Array,
  difficulty: number = DEFAULT_DIFFICULTY,
): Promise<string> {
  if (difficulty === 0) {
    return "0000000000000000";
  }

  const subtle = globalThis.crypto.subtle;
  const nonceBuf = new Uint8Array(8);
  let nonce = 0n;

  for (;;) {
    writeU64BE(nonceBuf, nonce);
    const msg = new Uint8Array(8 + body.length);
    msg.set(nonceBuf, 0);
    msg.set(body, 8);

    const hashBuf = await subtle.digest("SHA-256", msg);
    const hash = new Uint8Array(hashBuf);

    if (leadingZeroBits(hash) >= difficulty) {
      return hexEncode(nonceBuf);
    }
    nonce++;
  }
}

function hexEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += (b >> 4).toString(16) + (b & 0xf).toString(16);
  }
  return s;
}

export function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export { DEFAULT_DIFFICULTY };
