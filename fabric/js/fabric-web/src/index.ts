import {
  Fabric as FabricCore,
  wasmProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import * as libveritas from "@spacesprotocol/libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

let initPromise: Promise<void> | null = null;

function ensureInit(): Promise<void> {
  if (!initPromise) {
    const init = (libveritas as any).default ?? (libveritas as any).init ?? (libveritas as any).__wbg_init;
    initPromise = init ? Promise.resolve(init()).then(() => {}) : Promise.resolve();
  }
  return initPromise;
}

export class Fabric extends FabricCore {
  constructor(options?: FabricOptions) {
    super({ ...options, provider: wasmProvider(libveritas) });
  }

  async bootstrap(): Promise<void> {
    await ensureInit();
    return super.bootstrap();
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
  VerificationBadge,
  Resolved,
  ResolvedBatch,
} from "@spacesprotocol/fabric-core";

// Re-export WASM init for consumers who need manual control
export { ensureInit as init };

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
