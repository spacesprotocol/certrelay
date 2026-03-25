import { RelayPool } from "./pool.js";
import { compareHints, HintsResponse } from "./hints.js";
import { DEFAULT_SEEDS } from "./seeds.js";
import type {
  VeritasProvider,
  VeritasHandle,
  FabricZone,
  AnchorsHandle,
  QueryContextHandle,
  VerifiedMessageHandle,
} from "./provider.js";

export type VerificationBadge = "orange" | "unverified" | "none";

export interface Resolved {
  zone: FabricZone;
  roots: string[];  // hex-encoded
}

export interface ResolvedBatch {
  zones: FabricZone[];
  roots: string[];  // hex-encoded
}

export interface FabricOptions {
  provider: VeritasProvider;
  seeds?: string[];
  devMode?: boolean;
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

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
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
  private devMode: boolean;
  private _trusted: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  private _semiTrusted: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  private _observed: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  preferLatest: boolean;

  constructor(options: FabricOptions) {
    this.provider = options.provider;
    this.seeds = options.seeds ?? [...DEFAULT_SEEDS];
    this.devMode = options.devMode ?? false;
    this.preferLatest = options.preferLatest ?? true;
  }

  get relays(): string[] {
    return this.pool.urls;
  }

  /** The internal Veritas instance for offline verification. Null until bootstrap() is called. */
  getVeritas(): VeritasHandle | null {
    return this.veritas;
  }

  // ── Trust ──

  /** Trust a specific trust ID. Fetches anchors matching the given ID. */
  async trust(trustId: string): Promise<void> {
    if (this.needsPeers()) {
      await this.bootstrapPeers();
    }
    await this.updateAnchors(trustId, "trusted");
  }

  /** Trust from a QR code payload (the payload is the trust ID hex string). */
  async trustFromQr(payload: string): Promise<void> {
    await this.trust(payload.trim());
  }

  /** Returns the hex-encoded trust ID if anchors have been explicitly trusted, or null. */
  trusted(): string | null {
    return this._trusted ? toHex(this._trusted.id) : null;
  }

  /** Returns the hex-encoded observed trust ID from the latest anchor fetch, or null. */
  observed(): string | null {
    return this._observed ? toHex(this._observed.id) : null;
  }

  /** Set a semi-trusted anchor from an external source (e.g. public explorer). */
  async semiTrust(trustId: string): Promise<void> {
    if (this.needsPeers()) {
      await this.bootstrapPeers();
    }
    await this.updateAnchors(trustId, "semi_trusted");
  }

  /** Returns the hex-encoded semi-trusted trust ID, or null. */
  semiTrusted(): string | null {
    return this._semiTrusted ? toHex(this._semiTrusted.id) : null;
  }

  /** Clear the trusted anchor set. */
  clearTrusted(): void {
    this._trusted = null;
  }

  /** Compute a verification badge for a resolved handle. */
  badge(resolved: Resolved): VerificationBadge {
    const json = resolved.zone.toJson();
    const sovereignty: string = json?.sovereignty ?? "delegated";
    return this.badgeFor(sovereignty, resolved.roots);
  }

  /** Compute a verification badge given sovereignty type and roots. */
  badgeFor(sovereignty: string, roots: string[]): VerificationBadge {
    const isTrusted = this.areRootsTrusted(roots);
    const isObserved = isTrusted || this.areRootsObserved(roots);
    const isSemiTrusted = isTrusted || this.areRootsSemiTrusted(roots);

    if (isTrusted && sovereignty === "sovereign") {
      return "orange";
    }
    if (isObserved && !isTrusted && !isSemiTrusted) {
      return "unverified";
    }
    return "none";
  }

  private areRootsTrusted(roots: string[]): boolean {
    if (!this._trusted) return false;
    const trustedSet = new Set(this._trusted.roots.map(r => toHex(r)));
    return roots.every(root => trustedSet.has(root));
  }

  private areRootsObserved(roots: string[]): boolean {
    if (!this._observed) return false;
    const observedSet = new Set(this._observed.roots.map(r => toHex(r)));
    return roots.every(root => observedSet.has(root));
  }

  private areRootsSemiTrusted(roots: string[]): boolean {
    if (!this._semiTrusted) return false;
    const semiSet = new Set(this._semiTrusted.roots.map(r => toHex(r)));
    return roots.every(root => semiSet.has(root));
  }

  // ── Publish ──

  /** Publish a certificate and signed records to the network. */
  async publish(cert: Uint8Array, signedRecords: Uint8Array): Promise<void> {
    await this.bootstrap();

    const builder = this.provider.createMessageBuilder();
    builder.addHandle(cert, signedRecords);

    const chainProofReq = builder.chainProofRequest();
    const chainProof = await this.prove(chainProofReq);
    const msg = builder.build(chainProof);

    await this.broadcast(msg.toBytes());
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
      await this.updateAnchors();
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

  async updateAnchors(trustId?: string, kind: "trusted" | "semi_trusted" | "observed" = trustId ? "trusted" : "observed"): Promise<void> {
    let hash: string;
    let peers: string[];

    if (kind === "trusted" || kind === "semi_trusted") {
      hash = trustId!;
      peers = this.pool.shuffledUrls(4);
    } else {
      const result = await this.fetchLatestTrustId();
      hash = result.hash;
      peers = result.peers;
    }

    const anchors = await this.fetchAnchors(hash, peers);
    const trustSet = anchors.computeTrustSet();

    if (toHex(trustSet.id) !== hash) {
      throw new FabricError("anchor root mismatch", "decode");
    }

    this.veritas = this.provider.createVeritas(anchors);
    switch (kind) {
      case "trusted":
        this._trusted = trustSet;
        break;
      case "semi_trusted":
        this._semiTrusted = trustSet;
        break;
    }
    this._observed = trustSet;
  }

  // ── Resolution ──

  /** Resolve a single handle. Supports nested names like `hello.alice@bitcoin`. */
  async resolve(handle: string): Promise<Resolved> {
    const batch = await this.resolveAll([handle]);
    const zone = batch.zones.find((z) => z.handle === handle);
    if (!zone) {
      throw new FabricError(`${handle} not found`, "decode");
    }
    return { zone, roots: batch.roots };
  }

  /** Resolve multiple handles, including nested names like `hello.alice@bitcoin`. */
  async resolveAll(handles: string[]): Promise<ResolvedBatch> {
    const lookup = this.provider.createLookup(handles);
    const allZones: FabricZone[] = [];
    const roots: string[] = [];

    let prevBatch: string[] = [];
    let batch = lookup.start();
    while (batch.length > 0) {
      if (arraysEqual(batch, prevBatch)) break;
      const verified = await this.resolveFlat(batch);
      const zones = verified.zones();
      prevBatch = batch;
      batch = lookup.advance(zones);
      allZones.push(...zones);
      roots.push(toHex(verified.rootId()));
    }

    return {
      zones: lookup.expandZones(allZones),
      roots,
    };
  }

  /** Export a certificate chain for a handle. */
  async export(handle: string): Promise<Uint8Array> {
    const lookup = this.provider.createLookup([handle]);
    const allCertBytes: Uint8Array[] = [];

    let prevBatch: string[] = [];
    let batch = lookup.start();
    while (batch.length > 0) {
      if (arraysEqual(batch, prevBatch)) break;
      const verified = await this.resolveFlat(batch);
      allCertBytes.push(...verified.certificates());
      const zones = verified.zones();
      prevBatch = batch;
      batch = lookup.advance(zones);
    }

    return this.provider.createCertificateChain(handle, allCertBytes);
  }

  /** Resolve a flat list of non-dotted handles in a single relay query. */
  private async resolveFlat(handles: string[]): Promise<VerifiedMessageHandle> {
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
    return this.query(request);
  }

  private async query(request: QueryRequest): Promise<VerifiedMessageHandle> {
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

    const verified = await this.sendQuery(ctx, request, relays);
    const zones = verified.zones();

    // Cache root zones (spaces like "@bitcoin" or "#12-12")
    for (const zone of zones) {
      const handle = zone.handle;
      if (handle.startsWith("@") || handle.startsWith("#")) {
        this.zoneCache.set(handle, { bytes: zone.toBytes(), zone });
      }
    }

    return verified;
  }

  private async sendQuery(
    ctx: QueryContextHandle,
    request: QueryRequest,
    relays: string[],
  ): Promise<VerifiedMessageHandle> {
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
          const options = this.devMode ? 1 : 0; // bit 0 = dev mode
          const verified = this.veritas!.verifyWithOptions(ctx, bytes, options);
          this.pool.markAlive(url);
          return verified;
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

  async prove(request: string): Promise<Uint8Array> {
    await this.bootstrap();
    const urls = this.pool.shuffledUrls(4);
    let lastErr: Error = new FabricError("no peers available", "no_peers");

    for (const url of urls) {
      try {
        const resp = await fetch(`${url}/chain-proof`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: request,
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

  private async fetchLatestTrustId(): Promise<{
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

  private async fetchAnchors(
    hash: string,
    peers: string[],
  ): Promise<AnchorsHandle> {
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

        const json = await resp.json();
        return this.provider.createAnchors(json.entries);
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

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
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

