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
  mine,
  compareHints,
  DEFAULT_DIFFICULTY,
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
