/**
 * Abstraction over libveritas implementations.
 *
 * Two adapters are provided:
 *   - `wasmProvider()`   for `@spacesprotocol/libveritas` (browser/Node WASM)
 *   - `reactNativeProvider()` for `@spacesprotocol/react-native-libveritas`
 */

/** A verified zone returned from resolution. */
export interface FabricZone {
  handle(): string;
  toBytes(): Uint8Array;
  /** Returns the zone data as a parsed JS object. */
  toJson(): any;
}

export interface VerifiedMessageHandle {
  zones(): FabricZone[];
}

export interface QueryContextHandle {
  addRequest(handle: string): void;
  addZone(zoneBytes: Uint8Array): void;
}

export interface VeritasHandle {
  newestAnchor(): number;
  verifyMessage(
    ctx: QueryContextHandle,
    msg: Uint8Array,
  ): VerifiedMessageHandle;
}

export interface VeritasProvider {
  createVeritas(anchorsJson: any, devMode: boolean): VeritasHandle;
  createQueryContext(): QueryContextHandle;
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
  Veritas: { new (anchors: any): any; withDevMode(anchors: any): any };
  QueryContext: new () => any;
  Message: new (bytes: Uint8Array) => any;
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
    createVeritas(anchorsJson, devMode) {
      const v = devMode
        ? lib.Veritas.withDevMode(anchorsJson)
        : new lib.Veritas(anchorsJson);
      return {
        newestAnchor: () => v.newest_anchor(),
        verifyMessage(ctx, msg) {
          const vm = v.verify_message(getRaw(ctx), new lib.Message(msg));
          return {
            zones: () =>
              vm.zones().map(
                (z: any): FabricZone => ({
                  handle: () => z.handle(),
                  toBytes: () => z.to_bytes(),
                  toJson: () => z.to_json(),
                }),
              ),
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
  };
}

// ── React Native adapter (@spacesprotocol/react-native-libveritas) ──

export interface ReactNativeLibveritas {
  Veritas: { new (anchors: any): any; withDevMode(anchors: any): any };
  Anchors: { fromJson(json: string): any };
  QueryContext: new () => any;
  Message: new (bytes: ArrayBuffer) => any;
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
    createVeritas(anchorsJson, devMode) {
      const anchors = lib.Anchors.fromJson(JSON.stringify(anchorsJson));
      const v = devMode
        ? lib.Veritas.withDevMode(anchors)
        : new lib.Veritas(anchors);
      return {
        newestAnchor: () => v.newestAnchor(),
        verifyMessage(ctx, msg) {
          const msgBuf = msg.buffer.slice(
            msg.byteOffset,
            msg.byteOffset + msg.byteLength,
          );
          const vm = v.verifyMessage(getRaw(ctx), new lib.Message(msgBuf as ArrayBuffer));
          return {
            zones: () =>
              vm.zones().map(
                (z: any): FabricZone => ({
                  handle: () => z.handle(),
                  toBytes: () => new Uint8Array(z.toBytes()),
                  toJson: () => {
                    const json = z.toJson();
                    return typeof json === "string" ? JSON.parse(json) : json;
                  },
                }),
              ),
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
  };
}
