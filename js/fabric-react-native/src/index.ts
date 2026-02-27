import {
  Fabric as FabricCore,
  reactNativeProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import {
  Veritas,
  VeritasAnchors,
  VeritasQueryContext,
} from "@spacesprotocol/react-native-libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

export class Fabric extends FabricCore {
  constructor(options?: FabricOptions) {
    super({
      ...options,
      provider: reactNativeProvider({
        Veritas,
        VeritasAnchors,
        VeritasQueryContext,
      }),
    });
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
