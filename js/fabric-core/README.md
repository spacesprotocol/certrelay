# @spacesprotocol/fabric-core

Core certrelay client for the [Spaces protocol](https://spacesprotocol.org). Provider-agnostic - bring your own libveritas backend.

## Install

```bash
npm install @spacesprotocol/fabric-core
```

Most users should use a platform package instead, which bundles the correct libveritas backend automatically:

- **[@spacesprotocol/fabric-web](https://www.npmjs.com/package/@spacesprotocol/fabric-web)** — browsers and Node.js (WASM)
- **[@spacesprotocol/fabric-react-native](https://www.npmjs.com/package/@spacesprotocol/fabric-react-native)** — React Native (native)

## Usage

```ts
import { Fabric, wasmProvider } from "@spacesprotocol/fabric-core";
import * as libveritas from "@spacesprotocol/libveritas";

const fabric = new Fabric({ provider: wasmProvider(libveritas) });

// Resolve a handle
const zone = await fabric.resolve("alice@bitcoin");
console.log(zone.toJson());

// Resolve multiple handles at once
const zones = await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"]);

// Broadcast a signed message
await fabric.broadcast(messageBytes);
```

## Provider pattern

The core package defines a `VeritasProvider` interface. Two built-in adapters are provided:

- `wasmProvider(lib)` - wraps `@spacesprotocol/libveritas` (WASM)
- `reactNativeProvider(lib)` - wraps `@spacesprotocol/react-native-libveritas`

## API

### `new Fabric(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `provider` | `VeritasProvider` | *required* | Libveritas backend |
| `seeds` | `string[]` | built-in seeds | Bootstrap relay URLs |
| `anchorSetHash` | `string` | auto-discovered | Pin to a specific anchor set |
| `preferLatest` | `boolean` | `true` | Use hints to pick the freshest relay |

### Methods

| Method | Description |
|---|---|
| `resolve(handle)` | Resolve a single handle, returns `FabricZone` |
| `resolveAll(handles)` | Resolve multiple handles, returns `Map<string, FabricZone>` |
| `broadcast(msgBytes)` | Broadcast a signed message |
| `bootstrap()` | Discover peers and fetch anchors (called automatically) |
| `updateAnchors(hash?)` | Refresh the anchor set |
| `refreshPeers()` | Re-discover relay peers |
| `peers()` | List known peers |

## License

MIT
