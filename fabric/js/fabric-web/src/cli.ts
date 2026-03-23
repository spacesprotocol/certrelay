#!/usr/bin/env node
import { Fabric } from "./index.js";
import { DEFAULT_SEEDS } from "@spacesprotocol/fabric-core";

async function main() {
  const args = process.argv.slice(2);
  const handles: string[] = [];
  let seeds: string[] | undefined;
  let anchorSetHash: string | undefined;
  let devMode = false;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--seeds":
        i++;
        if (i >= args.length) exitUsage("--seeds requires a value");
        seeds = args[i].split(",");
        break;
      case "--anchor-set-hash":
        i++;
        if (i >= args.length) exitUsage("--anchor-set-hash requires a value");
        anchorSetHash = args[i];
        break;
      case "--dev-mode":
        devMode = true;
        break;
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
      default:
        if (args[i].startsWith("-")) exitUsage(`unknown option: ${args[i]}`);
        handles.push(args[i]);
    }
  }

  if (handles.length === 0) exitUsage("no handles specified");

  const fabric = new Fabric({
    seeds: seeds ?? DEFAULT_SEEDS,
    anchorSetHash,
    devMode,
  });

  const zones = await fabric.resolveAll(handles);

  for (const handle of handles) {
    const zone = zones.get(handle);
    if (!zone) {
      process.stderr.write(`${handle}: not found\n`);
      continue;
    }
    console.log(JSON.stringify(zone.toJson()));
  }
}

function printUsage() {
  console.log(
    `Usage: fabric [options] <handle> [<handle> ...]

Resolve handles via the certrelay network.

Options:
  --seeds <url,url,...>      Seed relay URLs (comma-separated)
  --anchor-set-hash <hex>    Anchor set hash for verification
  --dev-mode                 Enable dev mode (skip finality checks)
  -h, --help                 Show this help`,
  );
}

function exitUsage(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  printUsage();
  return process.exit(1);
}

main().catch((e) => {
  process.stderr.write(`error: ${e}\n`);
  process.exit(1);
});
