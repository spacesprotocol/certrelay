export { signMessage, verifyMessage } from "@spacesprotocol/fabric-core/signing";
import { schnorr } from "@noble/curves/secp256k1";
import * as libveritas from "@spacesprotocol/libveritas";

/**
 * Sign a record set and produce OffchainRecords bytes.
 *
 * @param recordSet - A RecordSet object (from `RecordSet.pack()`)
 * @param secretKey - 32-byte BIP-340 secret key
 * @returns OffchainRecords bytes ready for `fabric.publish()`
 */
export function signRecords(
  recordSet: { signingId(): Uint8Array; toBytes(): Uint8Array },
  secretKey: Uint8Array,
): Uint8Array {
  const sig = schnorr.sign(recordSet.signingId(), secretKey);
  return (libveritas as any).createOffchainRecords(recordSet.toBytes(), sig);
}
