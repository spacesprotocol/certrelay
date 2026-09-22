import { Fabric } from "@spacesprotocol/fabric-web";

const RELAY = "http://127.0.0.1:7778";
const HANDLE = "user@rad";

const fabric = new Fabric({
  seeds: [RELAY],
  devMode: true,
});

try {
  const { zone } = await fabric.resolve(HANDLE);
  console.log(JSON.stringify(zone.toJson(), null, 2));
} catch (e) {
  console.error(`Failed to resolve ${HANDLE}:`, e.message ?? e);
  process.exit(1);
}
