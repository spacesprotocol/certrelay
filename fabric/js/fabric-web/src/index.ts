import {
  Fabric as FabricCore,
  wasmProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import * as libveritas from "@spacesprotocol/libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

export class Fabric extends FabricCore {
  constructor(options?: FabricOptions) {
    super({ ...options, provider: wasmProvider(libveritas) });
  }
}

// Re-export useful types from core
export {
  FabricError,
  RelayPool,
  compareHints,
  DEFAULT_SEEDS,
} from "@spacesprotocol/fabric-core";

export type {
  FabricZone,
  PeerInfo,
  HintsResponse,
  SpaceHint,
  EpochResult,
  HandleHint,
} from "@spacesprotocol/fabric-core";

// Re-export libveritas types so consumers don't need a separate import
export {
  Anchors,
  Lookup,
  Message,
  MessageBuilder,
  OffchainRecords,
  QueryContext,
  Record,
  RecordSet,
  VerifiedMessage,
  Veritas,
  decodeZone,
  decode_certificate,
  hash_signable_message,
  verify_schnorr,
  verify_spaces_message,
  zoneIsBetterThan,
  zoneToBytes,
} from "@spacesprotocol/libveritas";
