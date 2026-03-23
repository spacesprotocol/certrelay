/**
 * Abstraction over libveritas implementations.
 *
 * Two adapters are provided:
 *   - `wasmProvider()`   for `@spacesprotocol/libveritas` (browser/Node WASM)
 *   - `reactNativeProvider()` for `@spacesprotocol/react-native-libveritas`
 */

/** A verified zone returned from resolution. */
export interface FabricZone {
  handle: string;
  toBytes(): Uint8Array;
  /** Returns the zone data as a parsed JS object. */
  toJson(): any;
}

export interface VerifiedMessageHandle {
  zones(): FabricZone[];
  certificates(): Uint8Array[];
}

export interface QueryContextHandle {
  addRequest(handle: string): void;
  addZone(zoneBytes: Uint8Array): void;
}

export interface AnchorsHandle {
  computeAnchorSetHash(): Uint8Array;
}

export interface VeritasHandle {
  newestAnchor(): number;
  verifyWithOptions(
    ctx: QueryContextHandle,
    msg: Uint8Array,
    options: number,
  ): VerifiedMessageHandle;
}

export interface LookupHandle {
  start(): string[];
  advance(zones: FabricZone[]): string[];
  expandZones(zones: FabricZone[]): FabricZone[];
}

export interface VeritasProvider {
  createAnchors(entriesJson: any): AnchorsHandle;
  createVeritas(anchors: AnchorsHandle): VeritasHandle;
  createQueryContext(): QueryContextHandle;
  createLookup(names: string[]): LookupHandle;
  createCertificateChain(subject: string, certBytesList: Uint8Array[]): Uint8Array;
}

// ── Symbol for accessing the underlying native object ──

const RAW: unique symbol = Symbol("raw");

export interface RawCarrier {
  [RAW]: any;
}

function getRaw(handle: QueryContextHandle): any {
  return (handle as unknown as RawCarrier)[RAW];
}

// ── WASM adapter (@spacesprotocol/libveritas) ──

export interface WasmLibveritas {
  Anchors: new (json: string) => any;
  Veritas: new (anchors: any) => any;
  QueryContext: new () => any;
  Message: new (bytes: Uint8Array) => any;
  Lookup: new (names: string[]) => any;
  zoneToBytes(zone: any): Uint8Array;
  createCertificateChain(subject: string, certBytesList: Uint8Array[]): Uint8Array;
}

/**
 * Create a provider backed by `@spacesprotocol/libveritas` (WASM).
 *
 * ```ts
 * import * as libveritas from '@spacesprotocol/libveritas';
 * const provider = wasmProvider(libveritas);
 * const fabric = new Fabric({ provider });
 * ```
 */
export function wasmProvider(lib: WasmLibveritas): VeritasProvider {
  return {
    createAnchors(entriesJson) {
      const anchors = new lib.Anchors(JSON.stringify(entriesJson));
      return {
        [RAW]: anchors,
        computeAnchorSetHash: () => anchors.computeAnchorSetHash(),
      } as unknown as AnchorsHandle;
    },
    createVeritas(anchorsHandle) {
      const anchors = (anchorsHandle as unknown as RawCarrier)[RAW];
      const v = new lib.Veritas(anchors);
      return {
        newestAnchor: () => v.newest_anchor(),
        verifyWithOptions(ctx, msg, options) {
          const vm = v.verifyWithOptions(getRaw(ctx), new lib.Message(msg), options);
          return {
            zones: () =>
              vm.zones().map(
                (z: any) => ({
                  get handle() { return z.handle; },
                  set handle(v: string) { z.handle = v; },
                  [RAW]: z,
                  toBytes: () => lib.zoneToBytes(z),
                  toJson: () => z,
                }) as unknown as FabricZone,
              ),
            certificates: () => {
              const certs: any[] = vm.certificates();
              return certs.map((c: any) => new Uint8Array(c));
            },
          };
        },
      };
    },
    createQueryContext() {
      const ctx = new lib.QueryContext();
      return {
        [RAW]: ctx,
        addRequest: (h: string) => ctx.add_request(h),
        addZone: (bytes: Uint8Array) => ctx.add_zone(bytes),
      } as QueryContextHandle;
    },
    createLookup(names) {
      const lookup = new lib.Lookup(names);
      return {
        start: () => lookup.start(),
        advance(zones) {
          const rawZones = zones.map((z) => (z as unknown as RawCarrier)[RAW]);
          return lookup.advance(rawZones);
        },
        expandZones(zones) {
          const rawZones = zones.map((z) => (z as unknown as RawCarrier)[RAW]);
          const expanded = lookup.expandZones(rawZones);
          return expanded.map(
            (z: any) => ({
              get handle() { return z.handle; },
              set handle(v: string) { z.handle = v; },
              [RAW]: z,
              toBytes: () => lib.zoneToBytes(z),
              toJson: () => z,
            }) as unknown as FabricZone,
          );
        },
      };
    },
    createCertificateChain(subject, certBytesList) {
      return lib.createCertificateChain(subject, certBytesList);
    },
  };
}

// ── React Native adapter (@spacesprotocol/react-native-libveritas) ──

export interface ReactNativeLibveritas {
  Veritas: new (anchors: any) => any;
  Anchors: { fromJson(json: string): any };
  QueryContext: new () => any;
  Message: new (bytes: ArrayBuffer) => any;
  Lookup: new (names: string[]) => any;
  zoneToBytes(zone: any): ArrayBuffer;
  zoneToJson(zone: any): string;
  createCertificateChain(subject: string, certBytesList: ArrayBuffer[]): ArrayBuffer;
}

/**
 * Create a provider backed by `@spacesprotocol/react-native-libveritas`.
 *
 * ```ts
 * import { Veritas, VeritasAnchors, VeritasQueryContext } from '@spacesprotocol/react-native-libveritas';
 * const provider = reactNativeProvider({ Veritas, VeritasAnchors, VeritasQueryContext });
 * const fabric = new Fabric({ provider });
 * ```
 */
export function reactNativeProvider(
  lib: ReactNativeLibveritas,
): VeritasProvider {
  return {
    createAnchors(entriesJson) {
      const anchors = lib.Anchors.fromJson(JSON.stringify(entriesJson));
      return {
        [RAW]: anchors,
        computeAnchorSetHash: () => new Uint8Array(anchors.computeAnchorSetHash()),
      } as unknown as AnchorsHandle;
    },
    createVeritas(anchorsHandle) {
      const anchors = (anchorsHandle as unknown as RawCarrier)[RAW];
      const v = new lib.Veritas(anchors);
      return {
        newestAnchor: () => v.newestAnchor(),
        verifyWithOptions(ctx, msg, options) {
          const msgBuf = msg.buffer.slice(
            msg.byteOffset,
            msg.byteOffset + msg.byteLength,
          );
          const vm = v.verifyWithOptions(getRaw(ctx), new lib.Message(msgBuf as ArrayBuffer), options);
          return {
            zones: () =>
              vm.zones().map(
                (z: any) => ({
                  get handle() { return z.handle; },
                  set handle(v: string) { z.handle = v; },
                  [RAW]: z,
                  toBytes: () => new Uint8Array(lib.zoneToBytes(z)),
                  toJson: () => {
                    const json = lib.zoneToJson(z);
                    return typeof json === "string" ? JSON.parse(json) : json;
                  },
                }) as unknown as FabricZone,
              ),
            certificates: () =>
              vm.certificates().map((c: any) => new Uint8Array(c)),
          };
        },
      };
    },
    createQueryContext() {
      const ctx = new lib.QueryContext();
      return {
        [RAW]: ctx,
        addRequest: (h: string) => ctx.addRequest(h),
        addZone: (bytes: Uint8Array) => {
          const buf = bytes.buffer.slice(
            bytes.byteOffset,
            bytes.byteOffset + bytes.byteLength,
          );
          ctx.addZone(buf);
        },
      } as QueryContextHandle;
    },
    createLookup(names) {
      const lookup = new lib.Lookup(names);
      return {
        start: () => lookup.start(),
        advance(zones) {
          const rawZones = zones.map((z) => (z as unknown as RawCarrier)[RAW]);
          return lookup.advance(rawZones);
        },
        expandZones(zones) {
          const rawZones = zones.map((z) => (z as unknown as RawCarrier)[RAW]);
          const expanded = lookup.expandZones(rawZones);
          return expanded.map(
            (z: any) => ({
              get handle() { return z.handle; },
              set handle(v: string) { z.handle = v; },
              [RAW]: z,
              toBytes: () => new Uint8Array(lib.zoneToBytes(z)),
              toJson: () => {
                const json = lib.zoneToJson(z);
                return typeof json === "string" ? JSON.parse(json) : json;
              },
            }) as unknown as FabricZone,
          );
        },
      };
    },
    createCertificateChain(subject, certBytesList) {
      const buffers = certBytesList.map((b) => {
        const buf = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
        return buf as ArrayBuffer;
      });
      return new Uint8Array(lib.createCertificateChain(subject, buffers));
    },
  };
}
