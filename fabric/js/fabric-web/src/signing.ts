export { signMessage, verifyMessage } from "@spacesprotocol/fabric-core/signing";
export { signRecords as signRecordsRaw } from "@spacesprotocol/fabric-core/signing";
import { signRecords as _signRecords } from "@spacesprotocol/fabric-core/signing";
import { OffchainRecords } from "@spacesprotocol/libveritas";

/**
 * Sign a record set and produce OffchainRecords bytes.
 *
 * @param recordSetBytes - Serialized record set bytes (e.g. `recordSet.toBytes()`)
 * @param secretKey - 32-byte BIP-340 secret key
 * @returns OffchainRecords bytes ready for `fabric.publish()`
 */
export function signRecords(
  recordSetBytes: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  return _signRecords(recordSetBytes, secretKey, (rs, sig) =>
    new OffchainRecords(rs, sig).toBytes()
  );
}
