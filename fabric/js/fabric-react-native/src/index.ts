import {
  Fabric as FabricCore,
  reactNativeProvider,
} from "@spacesprotocol/fabric-core";
import type { FabricOptions as CoreOptions } from "@spacesprotocol/fabric-core";
import { Veritas, Anchors, QueryContext, Message, Lookup, zoneToBytes, zoneToJson } from "@spacesprotocol/react-native-libveritas";

export type FabricOptions = Omit<CoreOptions, "provider">;

export class Fabric extends FabricCore {
  constructor(options?: FabricOptions) {
    super({
      ...options,
      provider: reactNativeProvider({
        Veritas,
        Anchors,
        QueryContext,
        Message,
        Lookup,
        zoneToBytes,
        zoneToJson,
      }),
    });
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
  QueryContext,
  RecordSet,
  VerifiedMessage,
  Veritas,
  Zone,
  createOffchainRecords,
  decodeCertificate,
  decodeZone,
  hashSignableMessage,
  verifySchnorr,
  verifySpacesMessage,
  zoneIsBetterThan,
  zoneToBytes,
  zoneToJson,
} from "@spacesprotocol/react-native-libveritas";
