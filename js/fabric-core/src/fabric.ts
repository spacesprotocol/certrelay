import { RelayPool } from "./pool.js";
import { compareHints, HintsResponse } from "./hints.js";
import { DEFAULT_SEEDS } from "./seeds.js";
import type {
  VeritasProvider,
  VeritasHandle,
  FabricZone,
  QueryContextHandle,
} from "./provider.js";

export interface FabricOptions {
  provider: VeritasProvider;
  seeds?: string[];
  anchorSetHash?: string;
  preferLatest?: boolean;
}

export interface PeerInfo {
  source_ip: string;
  url: string;
  capabilities: number;
}

interface EpochHint {
  root: string;
  height: number;
}

interface Query {
  space: string;
  handles: string[];
  epoch_hint?: EpochHint;
}

interface QueryRequest {
  queries: Query[];
}

interface AnchorEntry {
  block: { hash: string; height: number };
  spaces_root: string;
  ptrs_root: string | null;
}

interface AnchorResponse {
  root: string;
  entries: AnchorEntry[];
}

export class FabricError extends Error {
  constructor(
    message: string,
    public code:
      | "http"
      | "decode"
      | "verify"
      | "relay"
      | "no_peers" = "http",
    public status?: number,
  ) {
    super(message);
    this.name = "FabricError";
  }
}

/**
 * Certrelay client for JavaScript/TypeScript.
 *
 * Discovers relays, fetches and verifies certificates via the Spaces protocol.
 * Works with both WASM and React Native libveritas backends via the provider pattern.
 *
 * ```ts
 * // Browser / Node (WASM)
 * import * as libveritas from '@spacesprotocol/libveritas';
 * import { Fabric, wasmProvider } from '@spacesprotocol/fabric';
 * const fabric = new Fabric({ provider: wasmProvider(libveritas) });
 *
 * // React Native
 * import { Veritas, VeritasAnchors, VeritasQueryContext } from '@spacesprotocol/react-native-libveritas';
 * import { Fabric, reactNativeProvider } from '@spacesprotocol/fabric';
 * const fabric = new Fabric({ provider: reactNativeProvider({ Veritas, VeritasAnchors, VeritasQueryContext }) });
 * ```
 */
export class Fabric {
  private provider: VeritasProvider;
  private pool = new RelayPool();
  private veritas: VeritasHandle | null = null;
  private zoneCache = new Map<string, { bytes: Uint8Array; zone: FabricZone }>();
  private seeds: string[];
  private _anchorSetHash: string | null;
  preferLatest: boolean;

  constructor(options: FabricOptions) {
    this.provider = options.provider;
    this.seeds = options.seeds ?? [...DEFAULT_SEEDS];
    this._anchorSetHash = options.anchorSetHash ?? null;
    this.preferLatest = options.preferLatest ?? true;
  }

  get anchorSetHash(): string | null {
    return this._anchorSetHash;
  }

  get relays(): string[] {
    return this.pool.urls;
  }

  // ── Bootstrap ──

  private needsPeers(): boolean {
    return this.pool.isEmpty;
  }

  private needsAnchors(): boolean {
    return !this.veritas || this.veritas.newestAnchor() === 0;
  }

  async bootstrap(): Promise<void> {
    if (this.needsPeers()) {
      await this.bootstrapPeers();
    }
    if (this.needsAnchors()) {
      await this.updateAnchors(this._anchorSetHash ?? undefined);
    }
  }

  private async bootstrapPeers(): Promise<void> {
    const urls = new Set<string>(this.seeds);

    for (const seed of this.seeds) {
      try {
        const peers = await this.fetchPeers(seed);
        for (const peer of peers) {
          urls.add(peer.url);
        }
      } catch {
        // Seed unreachable, continue
      }
    }

    if (urls.size === 0) {
      throw new FabricError("no peers available", "no_peers");
    }

    this.pool.refresh(urls);
  }

  async updateAnchors(hash?: string): Promise<void> {
    let anchorSetHash: string;
    let peers: string[];

    if (hash) {
      anchorSetHash = hash;
      peers = this.pool.shuffledUrls(4);
    } else {
      const result = await this.fetchLatestAnchorSetHash();
      anchorSetHash = result.hash;
      peers = result.peers;
    }

    const anchors = await this.fetchAnchorSet(anchorSetHash, peers);
    this.veritas = this.provider.createVeritas(anchors.entries, false);
    this._anchorSetHash = anchorSetHash;
  }

  // ── Resolution ──

  async resolve(handle: string): Promise<FabricZone> {
    const zones = await this.resolveAll([handle]);
    const zone = zones.get(handle);
    if (!zone) {
      throw new FabricError(`${handle} not found`, "decode");
    }
    return zone;
  }

  async resolveAll(handles: string[]): Promise<Map<string, FabricZone>> {
    const bySpace = new Map<string, string[]>();
    for (const h of handles) {
      const { space, label } = parseHandle(h);
      const existing = bySpace.get(space) ?? [];
      existing.push(label);
      bySpace.set(space, existing);
    }

    const queries: Query[] = [];
    for (const [space, labels] of bySpace) {
      const q: Query = { space, handles: labels };
      const cached = this.zoneCache.get(space);
      if (cached) {
        const json = cached.zone.toJson();
        if (json?.commitment?.onchain) {
          q.epoch_hint = {
            root: json.commitment.onchain.state_root,
            height: json.commitment.onchain.block_height,
          };
        }
      }
      queries.push(q);
    }

    const request: QueryRequest = { queries };
    const verified = await this.query(request);

    const result = new Map<string, FabricZone>();
    for (const zone of verified) {
      result.set(zone.handle(), zone);
    }
    return result;
  }

  private async query(request: QueryRequest): Promise<FabricZone[]> {
    await this.bootstrap();

    const ctx = this.provider.createQueryContext();
    for (const q of request.queries) {
      const cached = this.zoneCache.get(q.space);
      if (cached) {
        ctx.addZone(cached.bytes);
      }
    }

    const relays = this.preferLatest
      ? await this.pickRelays(request, 4)
      : this.pool.shuffledUrls(4);

    const zones = await this.sendQuery(ctx, request, relays);

    // Cache root zones (spaces like "@bitcoin" or "#12-12")
    for (const zone of zones) {
      const handle = zone.handle();
      if (handle.startsWith("@") || handle.startsWith("#")) {
        this.zoneCache.set(handle, { bytes: zone.toBytes(), zone });
      }
    }

    return zones;
  }

  private async sendQuery(
    ctx: QueryContextHandle,
    request: QueryRequest,
    relays: string[],
  ): Promise<FabricZone[]> {
    // Build QueryContext with all requested handles
    for (const q of request.queries) {
      ctx.addRequest(q.space);
      for (const handle of q.handles) {
        if (handle) {
          ctx.addRequest(`${handle}${q.space}`);
        }
      }
    }

    let lastErr: Error = new FabricError("no peers available", "no_peers");

    for (const url of relays) {
      try {
        const resp = await fetch(`${url}/query`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(request),
        });

        if (!resp.ok) {
          const body = await resp.text();
          this.pool.markFailed(url);
          lastErr = new FabricError(
            `relay error (${resp.status}): ${body}`,
            "relay",
            resp.status,
          );
          continue;
        }

        const bytes = new Uint8Array(await resp.arrayBuffer());

        try {
          const verified = this.veritas!.verifyMessage(ctx, bytes);
          this.pool.markAlive(url);
          return verified.zones();
        } catch (e) {
          this.pool.markFailed(url);
          lastErr = new FabricError(
            `verification error: ${e}`,
            "verify",
          );
        }
      } catch (e) {
        this.pool.markFailed(url);
        lastErr =
          e instanceof FabricError
            ? e
            : new FabricError(`http error: ${e}`, "http");
      }
    }

    throw lastErr;
  }

  // ── Relay selection ──

  private async pickRelays(
    request: QueryRequest,
    count: number,
  ): Promise<string[]> {
    const hintsQuery = hintsQueryString(request);
    const shuffled = this.pool.shuffledUrls();
    const ranked: { url: string; hints: HintsResponse }[] = [];

    for (let i = 0; i < shuffled.length; i += count) {
      if (ranked.length >= count) break;

      const batch = shuffled.slice(i, i + count);
      const results = await Promise.allSettled(
        batch.map(async (url) => {
          const resp = await fetch(
            `${url}/hints?q=${encodeURIComponent(hintsQuery)}`,
          );
          if (!resp.ok) return null;
          const hints: HintsResponse = await resp.json();
          return { url, hints };
        }),
      );

      for (const result of results) {
        if (result.status === "fulfilled" && result.value) {
          ranked.push(result.value);
        }
      }
    }

    // Sort freshest first (b vs a for descending)
    ranked.sort((a, b) => compareHints(b.hints, a.hints));
    return ranked.map((r) => r.url);
  }

  // ── Chain proofs ──

  async prove(request: any): Promise<Uint8Array> {
    await this.bootstrap();
    const urls = this.pool.shuffledUrls(4);
    let lastErr: Error = new FabricError("no peers available", "no_peers");

    for (const url of urls) {
      try {
        const resp = await fetch(`${url}/chain-proof`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(request),
        });

        if (!resp.ok) {
          const body = await resp.text();
          this.pool.markFailed(url);
          lastErr = new FabricError(
            `relay error (${resp.status}): ${body}`,
            "relay",
            resp.status,
          );
          continue;
        }

        this.pool.markAlive(url);
        return new Uint8Array(await resp.arrayBuffer());
      } catch (e) {
        this.pool.markFailed(url);
        lastErr =
          e instanceof FabricError
            ? e
            : new FabricError(`http error: ${e}`, "http");
      }
    }

    throw lastErr;
  }

  // ── Broadcast ──

  async broadcast(msgBytes: Uint8Array): Promise<void> {
    await this.bootstrap();
    const urls = this.pool.shuffledUrls(4);
    if (urls.length === 0) {
      throw new FabricError("no peers available", "no_peers");
    }

    let anyOk = false;
    let lastErr: Error | null = null;

    for (const url of urls) {
      try {
        const resp = await fetch(`${url}/message`, {
          method: "POST",
          headers: {
            "content-type": "application/octet-stream",
          },
          body: msgBytes as unknown as BodyInit,
        });

        if (resp.ok) {
          anyOk = true;
        } else {
          const body = await resp.text();
          lastErr = new FabricError(
            `relay error (${resp.status}): ${body}`,
            "relay",
            resp.status,
          );
        }
      } catch (e) {
        lastErr = new FabricError(`http error: ${e}`, "http");
      }
    }

    if (!anyOk) {
      throw lastErr!;
    }
  }

  // ── Peers ──

  async peers(): Promise<PeerInfo[]> {
    const urls = this.pool.shuffledUrls(1);
    if (urls.length === 0) {
      throw new FabricError("no peers available", "no_peers");
    }
    return this.fetchPeers(urls[0]);
  }

  async refreshPeers(): Promise<void> {
    const current = this.pool.urls;
    const newUrls = new Set<string>();

    for (const url of current) {
      try {
        const peers = await this.fetchPeers(url);
        for (const peer of peers) {
          newUrls.add(peer.url);
        }
      } catch {
        // Continue on failure
      }
    }

    this.pool.refresh(newUrls);
    if (this.pool.isEmpty) {
      throw new FabricError("no peers available", "no_peers");
    }
  }

  // ── Internal fetch helpers ──

  private async fetchPeers(relayUrl: string): Promise<PeerInfo[]> {
    const resp = await fetch(`${relayUrl}/peers`);
    if (!resp.ok) {
      const body = await resp.text();
      throw new FabricError(
        `relay error (${resp.status}): ${body}`,
        "relay",
        resp.status,
      );
    }
    return resp.json();
  }

  private async fetchLatestAnchorSetHash(): Promise<{
    hash: string;
    peers: string[];
  }> {
    const votes = new Map<string, { height: number; peers: string[] }>();

    for (const url of this.seeds) {
      try {
        const resp = await fetch(`${url}/anchors`, { method: "HEAD" });
        const root = resp.headers.get("x-anchor-root");
        const height = parseInt(
          resp.headers.get("x-anchor-height") ?? "0",
          10,
        );
        if (root) {
          const key = `${root}:${height}`;
          const existing = votes.get(key);
          if (existing) {
            existing.peers.push(url);
          } else {
            votes.set(key, { height, peers: [url] });
          }
        }
      } catch {
        // Seed unreachable
      }
    }

    let best: { hash: string; peers: string[] } | null = null;
    let bestScore = -1;

    for (const [key, { height, peers }] of votes) {
      const root = key.split(":")[0];
      const score = peers.length * 1_000_000 + height;
      if (score > bestScore) {
        bestScore = score;
        best = { hash: root, peers };
      }
    }

    if (!best) {
      throw new FabricError("no peers available", "no_peers");
    }
    return best;
  }

  private async fetchAnchorSet(
    hash: string,
    peers: string[],
  ): Promise<AnchorResponse> {
    let lastErr: Error = new FabricError("no peers available", "no_peers");

    for (const url of peers) {
      try {
        const resp = await fetch(`${url}/anchors?root=${hash}`);
        if (!resp.ok) {
          const body = await resp.text();
          lastErr = new FabricError(
            `relay error (${resp.status}): ${body}`,
            "relay",
            resp.status,
          );
          continue;
        }

        const anchorSet: AnchorResponse = await resp.json();

        if (!(await rootMatches(anchorSet))) {
          continue;
        }

        return anchorSet;
      } catch (e) {
        lastErr =
          e instanceof FabricError
            ? e
            : new FabricError(`http error: ${e}`, "http");
      }
    }

    throw lastErr;
  }
}

// ── Utilities ──

function hintsQueryString(request: QueryRequest): string {
  const parts: string[] = [];
  for (const q of request.queries) {
    parts.push(q.space);
    for (const handle of q.handles) {
      parts.push(`${handle}${q.space}`);
    }
  }
  return parts.join(",");
}

function parseHandle(handle: string): { space: string; label: string } {
  let sepIdx = handle.indexOf("@");
  if (sepIdx < 0) {
    sepIdx = handle.indexOf("#");
  }
  if (sepIdx < 0) {
    throw new FabricError(`invalid handle: ${handle}`, "decode");
  }
  if (sepIdx === 0) {
    return { space: handle, label: "" };
  }
  return {
    space: handle.substring(sepIdx),
    label: handle.substring(0, sepIdx),
  };
}

function hexDecode(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

async function rootMatches(resp: AnchorResponse): Promise<boolean> {
  const computed = await computeAnchorSetHash(resp.entries);
  return computed === resp.root;
}

async function computeAnchorSetHash(entries: AnchorEntry[]): Promise<string> {
  const chunks: Uint8Array[] = [];
  for (const entry of entries) {
    chunks.push(hexDecode(entry.block.hash));

    const heightBuf = new Uint8Array(4);
    new DataView(heightBuf.buffer).setUint32(0, entry.block.height, true);
    chunks.push(heightBuf);

    chunks.push(hexDecode(entry.spaces_root));

    if (entry.ptrs_root) {
      chunks.push(hexDecode(entry.ptrs_root));
    } else {
      chunks.push(new Uint8Array(32));
    }
  }

  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const data = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.length;
  }

  const hashBuf = await globalThis.crypto.subtle.digest("SHA-256", data);
  return hexEncodeBytes(new Uint8Array(hashBuf));
}

function hexEncodeBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    s += (b >> 4).toString(16) + (b & 0xf).toString(16);
  }
  return s;
}
