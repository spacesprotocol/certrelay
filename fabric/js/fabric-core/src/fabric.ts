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

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function parseSecretKey(key: string | Uint8Array): Uint8Array {
  if (key instanceof Uint8Array) return key;
  if (typeof key === "string" && /^[0-9a-fA-F]{64}$/.test(key)) {
    return hexToBytes(key);
  }
  throw new FabricError("secretKey must be 32-byte Uint8Array or 64-char hex string", "decode");
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
export type SignSchnorrFn = (digest: Uint8Array, secretKey: Uint8Array) => Uint8Array;

export class Fabric {
  private static _signSchnorr: SignSchnorrFn | null = null;

  /**
   * Register a Schnorr signing function. Called automatically when
   * `@spacesprotocol/fabric-web/signing` is imported.
   */
  static registerSigner(fn: SignSchnorrFn): void {
    Fabric._signSchnorr = fn;
  }

  private provider: VeritasProvider;
  private pool = new RelayPool();
  private veritas: VeritasHandle | null = null;
  private zoneCache = new Map<string, { bytes: Uint8Array; zone: FabricZone }>();
  private seeds: string[];
  private devMode: boolean;
  private _trusted: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  private _semiTrusted: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  private _observed: { id: Uint8Array; roots: Uint8Array[] } | null = null;
  private anchorEntries: {
    trusted: any[] | null;
    semiTrusted: any[] | null;
    observed: any[] | null;
  } = { trusted: null, semiTrusted: null, observed: null };
  preferLatest: boolean;

  constructor(options: FabricOptions) {
    this.provider = options.provider;
    this.seeds = options.seeds ?? [...DEFAULT_SEEDS];
    this.devMode = options.devMode ?? false;
    this.preferLatest = options.preferLatest ?? true;
  }

  private rebuildVeritas(): void {
    const allEntries: any[] = [];
    for (const entries of [this.anchorEntries.trusted, this.anchorEntries.semiTrusted, this.anchorEntries.observed]) {
      if (entries) allEntries.push(...entries);
    }
    if (allEntries.length === 0) return;
    // Deduplicate by block height (keep first seen = highest priority from trusted > semi > observed)
    const seen = new Set<number>();
    const deduped = allEntries.filter(e => {
      const h = e.block?.height ?? e.height;
      if (seen.has(h)) return false;
      seen.add(h);
      return true;
    });
    const anchors = this.provider.createAnchors(deduped);
    this.veritas = this.provider.createVeritas(anchors);
  }

  get relays(): string[] {
    return this.pool.urls;
  }

  /** The internal Veritas instance for offline verification. Null until bootstrap() is called. */
  getVeritas(): VeritasHandle | null {
    return this.veritas;
  }

  // ── State persistence ──

  /** Export the current state as a JSON string for persistence. */
  saveState(): string {
    const zoneCacheObj: Record<string, any> = {};
    for (const [key, entry] of this.zoneCache) {
      zoneCacheObj[key] = entry.zone.toJson();
    }
    return JSON.stringify({
      version: 1,
      relays: this.pool.urls,
      anchors: {
        trusted: this.anchorEntries.trusted ?? [],
        semi_trusted: this.anchorEntries.semiTrusted ?? [],
        observed: this.anchorEntries.observed ?? [],
      },
      zone_cache: zoneCacheObj,
    });
  }

  /** Restore state from a previously saved JSON string. */
  loadState(json: string): void {
    const state = JSON.parse(json);
    if (state.relays?.length) {
      this.pool.refresh(state.relays);
    }
    if (state.anchors) {
      const a = state.anchors;
      if (a.trusted?.length) this.anchorEntries.trusted = a.trusted;
      if (a.semi_trusted?.length) this.anchorEntries.semiTrusted = a.semi_trusted;
      if (a.observed?.length) this.anchorEntries.observed = a.observed;
      this.rebuildVeritas();

      // Recompute trust sets from anchors
      if (this.anchorEntries.trusted && this.veritas) {
        const anchors = this.provider.createAnchors(this.anchorEntries.trusted);
        this._trusted = anchors.computeTrustSet();
      }
      if (this.anchorEntries.semiTrusted && this.veritas) {
        const anchors = this.provider.createAnchors(this.anchorEntries.semiTrusted);
        this._semiTrusted = anchors.computeTrustSet();
      }
      if (this.anchorEntries.observed && this.veritas) {
        const anchors = this.provider.createAnchors(this.anchorEntries.observed);
        this._observed = anchors.computeTrustSet();
      }
    }
    // Zone cache restoration would require re-parsing zones from JSON
    // which needs the provider. For now, zone cache is rebuilt on first resolve.
  }

  // ── Trust ──

  /** Trust a specific trust ID. Fetches anchors matching the given ID. */
  async trust(trustId: string): Promise<void> {
    if (this.needsPeers()) {
      await this.bootstrapPeers();
    }
    await this.updateAnchors(trustId, "trusted");
  }

  /** Parse a veritas://scan?id=... QR payload and pin as trusted. */
  async trustFromQr(payload: string): Promise<void> {
    const params = parseScanUri(payload);
    await this.trust(params.id);
  }

  /** Parse a veritas://scan?id=... QR payload and pin as semi-trusted. */
  async semiTrustFromQr(payload: string): Promise<void> {
    const params = parseScanUri(payload);
    await this.semiTrust(params.id);
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

  /** Compute a verification badge for a zone. */
  badge(zone: FabricZone): VerificationBadge {
    const json = zone.toJson();
    const sovereignty: string = json?.sovereignty ?? "delegated";
    const anchorHash: string | undefined = json?.anchor_hash;
    if (!anchorHash) return "unverified";
    return this.badgeFor(sovereignty, anchorHash);
  }

  /** Compute a verification badge given sovereignty type and an anchor hash. */
  badgeFor(sovereignty: string, anchorHash: string): VerificationBadge {
    if (!this._trusted && !this._observed && !this._semiTrusted) {
      return "unverified";
    }

    const isTrusted = this.isRootTrusted(anchorHash);
    const isObserved = isTrusted || this.isRootObserved(anchorHash);
    const isSemiTrusted = isTrusted || this.isRootSemiTrusted(anchorHash);

    if (isTrusted && sovereignty === "sovereign") {
      return "orange";
    }
    if (isObserved && !isTrusted && !isSemiTrusted) {
      return "unverified";
    }
    return "none";
  }

  private isRootTrusted(anchorHash: string): boolean {
    if (!this._trusted) return false;
    return this._trusted.roots.some(r => toHex(r) === anchorHash);
  }

  private isRootObserved(anchorHash: string): boolean {
    if (!this._observed) return false;
    return this._observed.roots.some(r => toHex(r) === anchorHash);
  }

  private isRootSemiTrusted(anchorHash: string): boolean {
    if (!this._semiTrusted) return false;
    return this._semiTrusted.roots.some(r => toHex(r) === anchorHash);
  }

  // ── Publish ──

  /**
   * Build and sign a message ready for broadcasting.
   *
   * Requires the signing module to be loaded first:
   * ```ts
   * import "@spacesprotocol/fabric-web/signing";
   * ```
   *
   * @param opts.cert - Certificate bytes (.spacecert)
   * @param opts.records - RecordSet or raw bytes
   * @param opts.secretKey - 32-byte secret key as Uint8Array or 64-char hex string
   * @param opts.primary - Set SIG_PRIMARY_ZONE flag for num id reverse mapping (default: true)
   * @returns Signed message bytes ready for broadcast()
   */
  async sign(opts: {
    cert: Uint8Array;
    records: Uint8Array | { toBytes(): Uint8Array };
    secretKey: string | Uint8Array;
    primary?: boolean;
  }): Promise<Uint8Array> {
    if (!Fabric._signSchnorr) {
      throw new FabricError(
        "signing module not loaded. Import '@spacesprotocol/fabric-web/signing' first.",
        "decode",
      );
    }
    await this.bootstrap();

    const { cert, primary = true } = opts;
    const records = opts.records instanceof Uint8Array ? opts.records : opts.records.toBytes();
    const key = parseSecretKey(opts.secretKey);
    const signFn = Fabric._signSchnorr;

    const builder = this.provider.createMessageBuilder();
    builder.addHandle(cert, records);

    const chainProofReq = builder.chainProofRequest();
    const chainProof = await this.prove(
      typeof chainProofReq === "string" ? chainProofReq : JSON.stringify(chainProofReq)
    );
    const { message, unsigned } = builder.build(chainProof);

    for (const u of unsigned) {
      if (primary) {
        u.setFlags(u.flags() | 0x01); // SIG_PRIMARY_ZONE
      }
      const sig = signFn(u.signingId(), key);
      const signed = u.packSig(sig);
      message.setRecords(u.canonical(), signed);
    }

    return message.toBytes();
  }

  /**
   * Build, sign, and broadcast a message.
   *
   * Requires the signing module to be loaded first:
   * ```ts
   * import "@spacesprotocol/fabric-web/signing";
   * ```
   *
   * @param opts.cert - Certificate bytes (.spacecert)
   * @param opts.records - RecordSet or raw bytes
   * @param opts.secretKey - 32-byte secret key as Uint8Array or 64-char hex string
   * @param opts.primary - Set SIG_PRIMARY_ZONE flag for num id reverse mapping (default: true)
   */
  async publish(opts: {
    cert: Uint8Array;
    records: Uint8Array | { toBytes(): Uint8Array };
    secretKey: string | Uint8Array;
    primary?: boolean;
  }): Promise<void> {
    const msg = await this.sign(opts);
    await this.broadcast(msg);
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

    const result = await this.fetchAnchors(hash, peers);
    const anchors = result.handle;
    const trustSet = anchors.computeTrustSet();

    if (toHex(trustSet.id) !== hash) {
      throw new FabricError("anchor root mismatch", "decode");
    }

    // Store entries per source and rebuild merged veritas
    switch (kind) {
      case "trusted":
        this.anchorEntries.trusted = result.entries;
        break;
      case "semi_trusted":
        this.anchorEntries.semiTrusted = result.entries;
        break;
      case "observed":
        this.anchorEntries.observed = result.entries;
        break;
    }
    this.rebuildVeritas();

    // Set trust field for this kind only
    switch (kind) {
      case "trusted":
        this._trusted = trustSet;
        break;
      case "semi_trusted":
        this._semiTrusted = trustSet;
        break;
      case "observed":
        this._observed = trustSet;
        break;
    }
  }

  // ── Resolution ──

  /** Resolve a single handle. Returns null if not found. Supports nested names like `hello.alice@bitcoin`. */
  async resolve(handle: string): Promise<FabricZone | null> {
    const zones = await this.resolveAll([handle]);
    return zones.find((z) => z.handle === handle) ?? null;
  }

  /** Resolve a numeric ID to a verified handle. */
  async resolveById(numId: string): Promise<FabricZone | null> {
    await this.bootstrap();
    const relays = this.pool.shuffledUrls(4);
    let lastErr: Error = new FabricError("reverse resolution failed", "no_peers");

    for (const url of relays) {
      try {
        const resp = await fetch(`${url}/reverse?ids=${encodeURIComponent(numId)}`);
        if (!resp.ok) continue;
        const records: { id: string; name: string }[] = await resp.json();
        const entry = records.find(r => r.id === numId);
        if (!entry) continue;

        let zone: FabricZone | null;
        try {
          zone = await this.resolve(entry.name);
        } catch (e) {
          lastErr = e instanceof Error ? e : new FabricError(String(e), "decode");
          continue;
        }
        if (!zone) continue;

        const json = zone.toJson();
        if (json?.num_id !== numId) {
          lastErr = new FabricError(`reverse mismatch: expected ${numId}`, "verify");
          continue;
        }

        return zone;
      } catch (e) {
        lastErr = e instanceof FabricError ? e : new FabricError(`reverse failed: ${e}`, "http");
      }
    }

    throw lastErr;
  }

  /** Search for handles by address record. Verifies results via forward resolution. */
  async searchAddr(name: string, addr: string): Promise<FabricZone[]> {
    await this.bootstrap();
    const relays = this.pool.shuffledUrls(4);
    let lastErr: Error = new FabricError("address search failed", "no_peers");

    for (const url of relays) {
      try {
        const resp = await fetch(
          `${url}/addrs?name=${encodeURIComponent(name)}&addr=${encodeURIComponent(addr)}`
        );
        if (!resp.ok) continue;
        const result: { address: string; handles: { handle: string; rev: string }[] } = await resp.json();
        if (!result.handles || result.handles.length === 0) continue;

        const revNames = result.handles.map(h => h.rev);
        let zones: FabricZone[];
        try {
          zones = await this.resolveAll(revNames);
        } catch (e) {
          lastErr = e instanceof Error ? e : new FabricError(String(e), "decode");
          continue;
        }

        // Filter to zones that actually have the matching addr record
        const matching = zones.filter(zone => {
          const json = zone.toJson();
          const records = json?.records;
          if (!Array.isArray(records)) return false;
          return records.some((r: any) =>
            r.type === "addr" && r.key === name &&
            Array.isArray(r.value) && r.value[0] === addr
          );
        });

        if (matching.length === 0) {
          lastErr = new FabricError("no verified matches", "verify");
          continue;
        }

        return matching;
      } catch (e) {
        lastErr = e instanceof FabricError ? e : new FabricError(`addr search failed: ${e}`, "http");
      }
    }

    throw lastErr;
  }

  /** Resolve multiple handles, including nested names like `hello.alice@bitcoin`. */
  async resolveAll(handles: string[]): Promise<FabricZone[]> {
    const lookup = this.provider.createLookup(handles);
    const allZones: FabricZone[] = [];

    let prevBatch: string[] = [];
    let batch = lookup.start();
    while (batch.length > 0) {
      if (arraysEqual(batch, prevBatch)) break;
      const verified = await this.resolveFlat(batch);
      const zones = verified.zones();
      prevBatch = batch;
      batch = lookup.advance(zones);
      allZones.push(...zones);
    }

    return lookup.expandZones(allZones);
  }

  /** Export a certificate chain for a handle. */
  async export(handle: string): Promise<Uint8Array> {
    const lookup = this.provider.createLookup([handle]);
    const allCertBytes: Uint8Array[] = [];

    let prevBatch: string[] = [];
    let batch = lookup.start();
    while (batch.length > 0) {
      if (arraysEqual(batch, prevBatch)) break;
      const verified = await this.resolveFlat(batch, false);
      allCertBytes.push(...verified.certificates());
      const zones = verified.zones();
      prevBatch = batch;
      batch = lookup.advance(zones);
    }

    return this.provider.createCertificateChain(handle, allCertBytes);
  }

  /** Resolve a flat list of non-dotted handles in a single relay query. */
  private async resolveFlat(handles: string[], hints = true): Promise<VerifiedMessageHandle> {
    const bySpace = new Map<string, string[]>();
    for (const h of handles) {
      const { space, label } = parseHandle(h);
      const existing = bySpace.get(space) ?? [];
      if (label) existing.push(label);
      bySpace.set(space, existing);
    }

    const queries: Query[] = [];
    for (const [space, labels] of bySpace) {
      const q: Query = { space, handles: labels };
      if (hints) {
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
        // Build GET query params
        const qParts: string[] = [];
        const hintParts: string[] = [];
        for (const q of request.queries) {
          qParts.push(q.space);
          for (const h of q.handles) {
            if (h) qParts.push(`${h}${q.space}`);
          }
          if (q.epoch_hint) {
            hintParts.push(`${q.space}:${q.epoch_hint.root}:${q.epoch_hint.height}`);
          }
        }
        let queryUrl = `${url}/query?q=${encodeURIComponent(qParts.join(","))}`;
        if (hintParts.length > 0) {
          queryUrl += `&hints=${encodeURIComponent(hintParts.join(","))}`;
        }

        const resp = await fetch(queryUrl);

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
  ): Promise<{ handle: AnchorsHandle; entries: any[] }> {
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
        return { handle: this.provider.createAnchors(json.entries), entries: json.entries };
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

// ── Scan URI ──

export interface ScanParams {
  id: string;  // hex-encoded trust ID
}

export function parseScanUri(uri: string): ScanParams {
  uri = uri.trim();
  const prefix = "veritas://scan?";
  if (!uri.startsWith(prefix)) {
    throw new FabricError("expected veritas://scan?... URI", "decode");
  }
  const query = uri.slice(prefix.length);
  const params = new URLSearchParams(query);
  const id = params.get("id");
  if (!id) {
    throw new FabricError("missing id parameter", "decode");
  }
  return { id };
}

// ── Utilities ──

function hintsQueryString(request: QueryRequest): string {
  const parts = new Set<string>();
  for (const q of request.queries) {
    parts.add(q.space);
    for (const handle of q.handles) {
      if (handle) parts.add(`${handle}${q.space}`);
    }
  }
  return [...parts].join(",");
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

