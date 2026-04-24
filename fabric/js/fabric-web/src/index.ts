import {
  Fabric as FabricCore,
  wasmProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import * as libveritas from "@spacesprotocol/libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

const wasmInit: (() => Promise<any>) | undefined = (() => {
  const d = (libveritas as any).default;
  if (typeof d === "function") return d;
  if (typeof (libveritas as any).__wbg_init === "function") return (libveritas as any).__wbg_init;
  // No async init needed — module self-initializes on import
  return undefined;
})();

let wasmReady: Promise<void> | null = null;

async function ensureInit(): Promise<void> {
  if (!wasmInit) return;
  if (!wasmReady) {
    wasmReady = wasmInit().catch(() => {
      // Already initialized (bundler environments) — safe to ignore
      wasmReady = Promise.resolve();
    });
  }
  await wasmReady;
}

/**
 * Initialize the WASM module manually. Usually not needed —
 * Fabric auto-initializes on first use. Call this if you need
 * to control when the WASM binary is loaded (e.g. during app startup).
 */
export async function init(): Promise<void> {
  await ensureInit();
}

export class Fabric extends FabricCore {
  constructor(options?: FabricOptions) {
    super({ ...options, provider: wasmProvider(libveritas) });
  }

  /** @internal Auto-initialize WASM before any network call. */
  override async bootstrap(): Promise<void> {
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
} from "@spacesprotocol/fabric-core";

// Re-export libveritas types so consumers don't need a separate import
export {
  Anchors,
  Lookup,
  Message,
  MessageBuilder,
  QueryContext,
  Record,
  RecordSet,
  VerifiedMessage,
  Veritas,
  decodeZone,
  decodeCertificate,
  hashSignableMessage,
  verifySpacesMessage,
  zoneIsBetterThan,
  zoneToBytes,
} from "@spacesprotocol/libveritas";
