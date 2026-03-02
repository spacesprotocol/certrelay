# @spacesprotocol/fabric-web

Certrelay client for browsers and Node.js. Uses the WASM build of libveritas under the hood.

## Install

```bash
npm install @spacesprotocol/fabric-web
```

## Usage

```ts
import { Fabric } from "@spacesprotocol/fabric-web";

const fabric = new Fabric();

const zone = await fabric.resolve("alice@bitcoin");
console.log(zone.toJson());
```

No provider configuration needed - the WASM libveritas backend is wired in automatically.

### Resolve multiple handles

```ts
const zones = await fabric.resolveAll(["alice@bitcoin", "bob@bitcoin"]);

for (const [handle, zone] of zones) {
  console.log(handle, zone.toJson());
}
```

### Broadcast a signed message

```ts
await fabric.broadcast(messageBytes);
```

### Options

```ts
const fabric = new Fabric({
  seeds: ["https://my-relay.example.com"],
  preferLatest: true,
});
```

| Option | Type | Default | Description |
|---|---|---|---|
| `seeds` | `string[]` | built-in seeds | Bootstrap relay URLs |
| `anchorSetHash` | `string` | auto-discovered | Pin to a specific anchor set |
| `preferLatest` | `boolean` | `true` | Use hints to pick the freshest relay |

## Platform packages

| Package | Environment |
|---|---|
| **@spacesprotocol/fabric-web** | Browsers, Node.js (WASM) |
| [@spacesprotocol/fabric-react-native](https://www.npmjs.com/package/@spacesprotocol/fabric-react-native) | React Native (native) |
| [@spacesprotocol/fabric-core](https://www.npmjs.com/package/@spacesprotocol/fabric-core) | Custom provider (advanced) |

## License

MIT
