import {
  Fabric as FabricCore,
  wasmProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import * as libveritas from "@spacesprotocol/libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

let initPromise: Promise<void> | null = null;

/**
 * Initialize the WASM module. Called automatically by `Fabric.create()`.
 * Safe to call multiple times — only runs once.
 */
export function init(): Promise<void> {
  if (!initPromise) {
    const initFn = (libveritas as any).default ?? (libveritas as any).init ?? (libveritas as any).__wbg_init;
    initPromise = initFn ? Promise.resolve(initFn()).then(() => {}) : Promise.resolve();
  }
  return initPromise;
}

export class Fabric extends FabricCore {
  private constructor(options?: FabricOptions) {
    super({ ...options, provider: wasmProvider(libveritas) });
  }

  /**
   * Create a new Fabric instance. Initializes WASM if needed.
   */
  static async create(options?: FabricOptions): Promise<Fabric> {
    await init();
    return new Fabric(options);
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
