from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
from urllib.request import Request, urlopen
from urllib.parse import urlencode

import libveritas as lv

from .seeds import DEFAULT_SEEDS
from .hints import (
    CompareHints,
    EpochResult,
    HandleHint,
    HintsResponse,
    SpaceHint,
)
from .pool import RelayPool


BADGE_ORANGE = "orange"
BADGE_UNVERIFIED = "unverified"
BADGE_NONE = "none"


class FabricError(Exception):
    def __init__(self, code: str, message: str, status: int = 0):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(f"{code}: {message}" if status == 0
                         else f"{code} ({status}): {message}")



@dataclass
class _EpochHint:
    root: str
    height: int


@dataclass
class _Query:
    space: str
    handles: list[str]
    epoch_hint: Optional[_EpochHint] = None

    def to_dict(self) -> dict:
        d: dict = {"space": self.space, "handles": self.handles}
        if self.epoch_hint is not None:
            d["epoch_hint"] = {
                "root": self.epoch_hint.root,
                "height": self.epoch_hint.height,
            }
        return d


@dataclass
class _QueryRequest:
    queries: list[_Query]

    def to_json(self) -> bytes:
        return json.dumps(
            {"queries": [q.to_dict() for q in self.queries]}
        ).encode()


class _TrustKind:
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    OBSERVED = "observed"


class _AnchorPool:
    def __init__(self):
        self.trusted: list = []      # raw entries list (from JSON)
        self.semi_trusted: list = [] # raw entries list (from JSON)
        self.observed: list = []     # raw entries list (from JSON)

    def merged(self) -> list:
        """Combine all entries, dedup by block height."""
        all_entries = []
        all_entries.extend(self.trusted)
        all_entries.extend(self.semi_trusted)
        all_entries.extend(self.observed)
        seen = set()
        deduped = []
        for e in all_entries:
            h = e.get("block", {}).get("height", 0) if isinstance(e, dict) else 0
            if h not in seen:
                seen.add(h)
                deduped.append(e)
        deduped.sort(
            key=lambda e: e.get("block", {}).get("height", 0) if isinstance(e, dict) else 0,
            reverse=True,
        )
        return deduped


@dataclass
class ScanParams:
    """Parsed parameters from a veritas://scan?... URI."""
    id: str  # hex-encoded trust ID

    @staticmethod
    def parse(uri: str) -> "ScanParams":
        uri = uri.strip()
        prefix = "veritas://scan?"
        if not uri.startswith(prefix):
            raise FabricError("decode", "expected veritas://scan?... URI")
        query = uri[len(prefix):]
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v
        trust_id = params.get("id")
        if not trust_id:
            raise FabricError("decode", "missing id parameter")
        return ScanParams(id=trust_id)


class Fabric:
    def __init__(
        self,
        seeds: Optional[list[str]] = None,
        *,
        dev_mode: bool = False,
        prefer_latest: bool = True,
    ):
        self._seeds = seeds or list(DEFAULT_SEEDS)
        self._dev_mode = dev_mode
        self._prefer_latest = prefer_latest
        self._pool = RelayPool()
        self._veritas: Optional[lv.Veritas] = None
        self._trusted: Optional[lv.TrustSet] = None
        self._observed: Optional[lv.TrustSet] = None
        self._semi_trusted: Optional[lv.TrustSet] = None
        self._anchor_pool = _AnchorPool()
        self._zone_cache: dict[str, lv.Zone] = {}
        self._lock = threading.Lock()

    @property
    def relays(self) -> list[str]:
        return self._pool.urls()

    @property
    def veritas(self) -> Optional[lv.Veritas]:
        """The internal Veritas instance for offline verification. None until bootstrap() is called."""
        with self._lock:
            return self._veritas

    # -- Public API --

    def trust(self, trust_id: str) -> None:
        """Pin a specific trust ID (hex-encoded 32-byte hash).
        Bootstraps peers if needed, then fetches the anchor set for this ID."""
        if self._pool.is_empty():
            self._bootstrap_peers()
        self._update_anchors(trust_id, _TrustKind.TRUSTED)

    def trust_from_qr(self, payload: str) -> None:
        """Parse a veritas://scan?id=... QR payload and pin as trusted."""
        params = ScanParams.parse(payload)
        self.trust(params.id)

    def semi_trust_from_qr(self, payload: str) -> None:
        """Parse a veritas://scan?id=... QR payload and pin as semi-trusted."""
        params = ScanParams.parse(payload)
        self.semi_trust(params.id)

    def trusted(self) -> Optional[str]:
        """Return the hex-encoded trusted trust ID, or None if not set."""
        ts = self._trusted
        return bytes(ts.id).hex() if ts else None

    def observed(self) -> Optional[str]:
        """Return the hex-encoded observed trust ID, or None if not set."""
        ts = self._observed
        return bytes(ts.id).hex() if ts else None

    def semi_trust(self, trust_id: str) -> None:
        """Set a semi-trusted anchor from an external source (e.g. public explorer)."""
        if self._pool.is_empty():
            self._bootstrap_peers()
        self._update_anchors(trust_id, _TrustKind.SEMI_TRUSTED)

    def semi_trusted(self) -> Optional[str]:
        """Return the hex-encoded semi-trusted trust ID, or None if not set."""
        ts = self._semi_trusted
        return bytes(ts.id).hex() if ts else None

    def clear_trusted(self) -> None:
        """Clear the pinned trusted state."""
        self._trusted = None

    def badge(self, zone: lv.Zone) -> str:
        """Return the verification badge for a Zone."""
        return self.badge_for(zone.sovereignty, zone.anchor_hash)

    def badge_for(self, sovereignty: str, anchor_hash: str) -> str:
        """Return the verification badge given sovereignty and an anchor hash."""
        if self._trusted is None and self._observed is None and self._semi_trusted is None:
            return BADGE_UNVERIFIED
        is_trusted = self._is_root_trusted(anchor_hash)
        is_observed = is_trusted or self._is_root_observed(anchor_hash)
        is_semi_trusted = is_trusted or self._is_root_semi_trusted(anchor_hash)
        if is_trusted and sovereignty == "sovereign":
            return BADGE_ORANGE
        if is_observed and not is_trusted and not is_semi_trusted:
            return BADGE_UNVERIFIED
        return BADGE_NONE

    def resolve(self, handle: str) -> lv.Zone | None:
        zones = self.resolve_all([handle])
        return next((z for z in zones if z.handle == handle), None)

    def resolve_by_id(self, num_id: str) -> lv.Zone | None:
        """Resolve a numeric ID to a verified handle. Returns None if not found."""
        self.bootstrap()
        urls = self._pool.shuffled_urls(4)
        last_err: Exception = FabricError("no_peers", "reverse resolution failed")

        for u in urls:
            try:
                req = Request(u + "/reverse?ids=" + num_id)
                with urlopen(req, timeout=10) as resp:
                    if resp.status >= 300:
                        self._pool.mark_failed(u)
                        continue
                    entries = json.loads(resp.read())
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = FabricError("http", str(e))
                continue

            entry = next((e for e in entries if e.get("id") == num_id), None)
            if entry is None:
                continue

            zone = self.resolve(entry["name"])
            if zone is None:
                continue

            if getattr(zone, "num_id", None) != num_id:
                last_err = FabricError("verify", f"num_id mismatch: expected {num_id}")
                continue

            self._pool.mark_alive(u)
            return zone

        return None

    def search_addr(self, name: str, addr: str) -> list[lv.Zone]:
        """Search for handles by address record, verify via forward resolution."""
        self.bootstrap()
        urls = self._pool.shuffled_urls(4)
        last_err: Exception = FabricError("no_peers", "address search failed")

        for u in urls:
            try:
                req = Request(f"{u}/addrs?name={name}&addr={addr}")
                with urlopen(req, timeout=10) as resp:
                    if resp.status >= 300:
                        self._pool.mark_failed(u)
                        continue
                    result = json.loads(resp.read())
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = FabricError("http", str(e))
                continue

            handles = result.get("handles", [])
            if not handles:
                continue

            rev_names = [h["rev"] for h in handles]
            try:
                zones = self.resolve_all(rev_names)
            except Exception as e:
                last_err = e
                continue

            # Filter to zones that actually contain the matching addr record
            matching = []
            for z in zones:
                if z.records is not None:
                    try:
                        rs = lv.RecordSet(z.records)
                        for r in rs.unpack():
                            if hasattr(r, 'key') and hasattr(r, 'value'):
                                if r.key == name and len(r.value) > 0 and r.value[0] == addr:
                                    matching.append(z)
                                    break
                    except Exception:
                        continue

            if not matching:
                continue

            self._pool.mark_alive(u)
            return matching

        raise last_err

    def resolve_all(self, handles: list[str]) -> list[lv.Zone]:
        lookup = lv.Lookup(handles)
        all_zones: list[lv.Zone] = []

        prev_batch: list[str] = []
        batch = lookup.start()
        while batch:
            if batch == prev_batch:
                break
            verified = self._resolve_flat(batch, hints=True)
            zones = verified.zones()
            prev_batch = batch
            batch = lookup.advance(zones)
            all_zones.extend(zones)

        return lookup.expand_zones(all_zones)

    def export(self, handle: str) -> bytes:
        """Export a certificate chain for a handle in .spacecert format."""
        lookup = lv.Lookup([handle])
        all_cert_bytes: list[bytes] = []

        prev_batch: list[str] = []
        batch = lookup.start()
        while batch:
            if batch == prev_batch:
                break
            verified = self._resolve_flat(batch, hints=False)
            all_cert_bytes.extend(verified.certificates())
            zones = verified.zones()
            prev_batch = batch
            batch = lookup.advance(zones)

        return lv.create_certificate_chain(handle, all_cert_bytes)

    def bootstrap(self):
        if self._pool.is_empty():
            self._bootstrap_peers()
        if self._veritas is None or self._veritas.newest_anchor() == 0:
            self._update_anchors()

    def sign(self, cert: bytes, records: bytes, secret_key: bytes, primary: bool = True) -> bytes:
        """Build and sign a message. Returns message bytes."""
        self.bootstrap()
        builder = lv.MessageBuilder()
        builder.add_handle(cert, records)
        proof_req_json = builder.chain_proof_request()
        proof_bytes = self.prove(proof_req_json.encode())
        result = builder.build(proof_bytes)

        for u in result.unsigned:
            if primary:
                u.set_flags(u.flags() | 0x01)
            sig = lv.sign_schnorr(u.signing_id(), secret_key)
            signed = u.pack_sig(sig)
            result.message.set_records(u.canonical(), signed)

        return result.message.to_bytes()

    def publish(self, cert: bytes, records: bytes, secret_key: bytes, primary: bool = True) -> None:
        """Build, sign, and broadcast a message."""
        msg = self.sign(cert, records, secret_key, primary)
        self.broadcast(msg)

    def prove(self, request: bytes) -> bytes:
        """Request a chain proof from a relay."""
        self.bootstrap()
        urls = self._pool.shuffled_urls(4)
        last_err: Exception = FabricError("no_peers", "no peers available")

        for u in urls:
            try:
                resp = _post_json(u + "/chain-proof", request)
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = e
                continue
            self._pool.mark_alive(u)
            return resp

        raise last_err

    def broadcast(self, msg_bytes: bytes) -> None:
        """Send a message to up to 4 random relays for gossip propagation."""
        self.bootstrap()
        urls = self._pool.shuffled_urls(4)
        if not urls:
            raise FabricError("no_peers", "no peers available")

        any_ok = False
        last_err: Optional[Exception] = None
        for u in urls:
            try:
                _post_binary(u + "/message", msg_bytes)
                any_ok = True
            except Exception as e:
                last_err = e
        if not any_ok:
            raise last_err or FabricError("no_peers", "no peers available")

    def peers(self) -> list[dict]:
        urls = self._pool.shuffled_urls(1)
        if not urls:
            raise FabricError("no_peers", "no peers available")
        return _fetch_peers(urls[0])

    def refresh_peers(self):
        current = self._pool.urls()
        new_urls = []
        for u in current:
            try:
                for p in _fetch_peers(u):
                    new_urls.append(p["url"])
            except Exception:
                pass
        self._pool.refresh(new_urls)
        if self._pool.is_empty():
            raise FabricError("no_peers", "no peers available")

    # -- Internal --

    def _is_root_trusted(self, anchor_hash: str) -> bool:
        ts = self._trusted
        if ts is None:
            return False
        root_bytes = bytes.fromhex(anchor_hash)
        return any(bytes(r) == root_bytes for r in ts.roots)

    def _is_root_observed(self, anchor_hash: str) -> bool:
        ts = self._observed
        if ts is None:
            return False
        root_bytes = bytes.fromhex(anchor_hash)
        return any(bytes(r) == root_bytes for r in ts.roots)

    def _is_root_semi_trusted(self, anchor_hash: str) -> bool:
        ts = self._semi_trusted
        if ts is None:
            return False
        root_bytes = bytes.fromhex(anchor_hash)
        return any(bytes(r) == root_bytes for r in ts.roots)

    def _bootstrap_peers(self):
        urls: set[str] = set()
        for seed in self._seeds:
            urls.add(seed)
            try:
                for p in _fetch_peers(seed):
                    urls.add(p["url"])
            except Exception:
                pass
        if not urls:
            raise FabricError("no_peers", "no peers available")
        self._pool.refresh(list(urls))

    def _update_anchors(self, trust_id: Optional[str] = None, kind: str = ""):
        if not kind:
            kind = _TrustKind.TRUSTED if (trust_id is not None and trust_id != "") else _TrustKind.OBSERVED

        if kind == _TrustKind.TRUSTED or kind == _TrustKind.SEMI_TRUSTED:
            anchor_hash = trust_id
            peers = self._pool.shuffled_urls(4)
        else:
            anchor_hash, peers = self._fetch_latest_trust_id()

        anchors, entries = self._fetch_anchors(anchor_hash, peers)
        trust_set = anchors.compute_trust_set()
        if bytes(trust_set.id).hex() != anchor_hash:
            raise FabricError("decode", "anchor root mismatch")

        with self._lock:
            if kind == _TrustKind.TRUSTED:
                self._anchor_pool.trusted = entries
            elif kind == _TrustKind.SEMI_TRUSTED:
                self._anchor_pool.semi_trusted = entries
            else:
                self._anchor_pool.observed = entries

            # Rebuild veritas from merged anchors
            merged = self._anchor_pool.merged()
            if merged:
                merged_anchors = lv.Anchors.from_json(json.dumps(merged))
                self._veritas = lv.Veritas(merged_anchors)

            if kind == _TrustKind.TRUSTED:
                self._trusted = trust_set
            elif kind == _TrustKind.SEMI_TRUSTED:
                self._semi_trusted = trust_set
            else:
                self._observed = trust_set

    def _resolve_flat(self, handles: list[str], *, hints: bool = True) -> lv.VerifiedMessage:
        by_space: dict[str, list[str]] = {}
        for h in handles:
            space, label = _parse_handle(h)
            by_space.setdefault(space, []).append(label)

        queries = []
        for space, labels in by_space.items():
            q = _Query(space=space, handles=labels)
            if hints:
                with self._lock:
                    cached = self._zone_cache.get(space)
                    if cached is not None:
                        hint = _epoch_hint_from_zone(cached)
                        if hint is not None:
                            q.epoch_hint = hint
            queries.append(q)

        return self._query(_QueryRequest(queries=queries))

    def _query(self, request: _QueryRequest) -> lv.VerifiedMessage:
        self.bootstrap()

        ctx = lv.QueryContext()
        with self._lock:
            for q in request.queries:
                cached = self._zone_cache.get(q.space)
                if cached is not None:
                    try:
                        ctx.add_zone(lv.zone_to_bytes(cached))
                    except Exception:
                        pass

        if self._prefer_latest:
            relays = self._pick_relays(request, 4)
        else:
            relays = self._pool.shuffled_urls(4)

        verified = self._send_query(ctx, request, relays)

        zones = verified.zones()
        with self._lock:
            for z in zones:
                if z.handle.startswith("@") or z.handle.startswith("#"):
                    self._zone_cache[z.handle] = z

        return verified

    def _send_query(
        self,
        ctx: lv.QueryContext,
        request: _QueryRequest,
        relays: list[str],
    ) -> lv.VerifiedMessage:
        q_parts: list[str] = []
        hint_parts: list[str] = []
        for q in request.queries:
            ctx.add_request(q.space)
            q_parts.append(q.space)
            for h in q.handles:
                if h:
                    ctx.add_request(h + q.space)
                    q_parts.append(h + q.space)
            if q.epoch_hint is not None:
                hint_parts.append(
                    f"{q.space}:{q.epoch_hint.root}:{q.epoch_hint.height}"
                )

        last_err: Exception = FabricError("no_peers", "no peers available")

        for u in relays:
            try:
                params = {"q": ",".join(q_parts)}
                if hint_parts:
                    params["hints"] = ",".join(hint_parts)
                query_url = u + "/query?" + urlencode(params)
                req = Request(query_url)
                with urlopen(req, timeout=10) as resp:
                    resp_bytes = resp.read()
                    if resp.status >= 300:
                        self._pool.mark_failed(u)
                        last_err = FabricError("relay", resp_bytes.decode(), resp.status)
                        continue
            except FabricError:
                raise
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = e
                continue

            try:
                msg = lv.Message(resp_bytes)
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = FabricError("decode", f"{u}/query: {e}")
                continue

            with self._lock:
                v = self._veritas
            if v is None:
                raise FabricError("no_peers", "no veritas instance")

            try:
                options = lv.verify_dev_mode() if self._dev_mode else 0
                verified = v.verify_with_options(ctx, msg, options)
            except Exception as e:
                self._pool.mark_failed(u)
                last_err = FabricError("verify", str(e))
                continue

            self._pool.mark_alive(u)
            return verified

        raise last_err

    def _pick_relays(self, request: _QueryRequest, count: int) -> list[str]:
        hints_query = _hints_query_string(request)
        shuffled = self._pool.shuffled_urls(0)

        results: list[tuple[str, HintsResponse]] = []

        for i in range(0, len(shuffled), count):
            if len(results) >= count:
                break
            batch = shuffled[i : i + count]

            with ThreadPoolExecutor(max_workers=len(batch)) as pool:
                futures = {
                    pool.submit(_fetch_hints, u, hints_query): u for u in batch
                }
                for fut in as_completed(futures):
                    u = futures[fut]
                    try:
                        h = fut.result()
                        results.append((u, h))
                    except Exception:
                        self._pool.mark_failed(u)

        from functools import cmp_to_key
        results.sort(key=cmp_to_key(lambda a, b: -CompareHints(a[1], b[1])))

        return [r[0] for r in results]

    def _fetch_latest_trust_id(self) -> tuple[str, list[str]]:
        votes: dict[str, dict] = {}

        for seed in self._seeds:
            try:
                req = Request(seed + "/anchors", method="HEAD")
                with urlopen(req, timeout=10) as resp:
                    root = resp.headers.get("X-Anchor-Root", "")
                    height_str = resp.headers.get("X-Anchor-Height", "0")
                    height = int(height_str) if height_str else 0
            except Exception:
                continue

            if root:
                key = f"{root}:{height}"
                if key in votes:
                    votes[key]["peers"].append(seed)
                else:
                    votes[key] = {"height": height, "peers": [seed]}

        best_key = ""
        best_score = -1
        for key, v in votes.items():
            score = len(v["peers"]) * 1_000_000 + v["height"]
            if score > best_score:
                best_score = score
                best_key = key

        if not best_key:
            raise FabricError("no_peers", "no peers available")

        parts = best_key.split(":", 1)
        return parts[0], votes[best_key]["peers"]

    def _fetch_anchors(
        self, hash_str: str, peers: list[str]
    ) -> tuple[lv.Anchors, list]:
        last_err: Exception = FabricError("no_peers", "no peers available")

        for u in peers:
            try:
                req = Request(u + "/anchors?root=" + hash_str)
                with urlopen(req, timeout=10) as resp:
                    if resp.status >= 300:
                        last_err = FabricError(
                            "relay", resp.read().decode(), resp.status
                        )
                        continue
                    body = json.loads(resp.read())
            except FabricError:
                raise
            except Exception as e:
                last_err = FabricError("http", str(e))
                continue

            entries = body.get("entries")
            if entries is None:
                last_err = FabricError(
                    "decode", "missing entries in anchor response"
                )
                continue

            try:
                anchors = lv.Anchors.from_json(json.dumps(entries))
            except Exception as e:
                last_err = FabricError("decode", f"parsing anchors: {e}")
                continue

            return anchors, entries

        raise last_err


# -- Utilities --


def _parse_handle(handle: str) -> tuple[str, str]:
    """Returns (space, label)."""
    for i, c in enumerate(handle):
        if c in ("@", "#"):
            if i == 0:
                return handle, ""
            return handle[i:], handle[:i]
    return handle, ""


def _hints_query_string(request: _QueryRequest) -> str:
    parts: set[str] = set()
    for q in request.queries:
        parts.add(q.space)
        for h in q.handles:
            parts.add(h + q.space)
    return ",".join(parts)


def _epoch_hint_from_zone(z: lv.Zone) -> Optional[_EpochHint]:
    if z.commitment.is_exists():
        return _EpochHint(
            root=z.commitment.state_root.hex(),
            height=z.commitment.block_height,
        )
    return None


def _fetch_peers(relay_url: str) -> list[dict]:
    req = Request(relay_url + "/peers")
    with urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise FabricError("relay", resp.read().decode(), resp.status)
        return json.loads(resp.read())


def _fetch_hints(relay_url: str, query: str) -> HintsResponse:
    url = relay_url + "/hints?" + urlencode({"q": query})
    req = Request(url)
    with urlopen(req, timeout=10) as resp:
        if resp.status >= 300:
            raise FabricError("relay", f"hints: status {resp.status}")
        data = json.loads(resp.read())

    return HintsResponse(
        anchor_tip=data.get("anchor_tip", 0),
        spaces=[
            SpaceHint(
                space=s["space"],
                epoch_tip=s["epoch_tip"],
                seq=s["seq"],
                delegate_seq=s["delegate_seq"],
            )
            for s in data.get("spaces", [])
        ],
        epochs=[
            EpochResult(
                epoch_tip=e["epoch_tip"],
                handles=[
                    HandleHint(handle=h["handle"], seq=h["seq"])
                    for h in e.get("handles", [])
                ],
            )
            for e in data.get("epochs", [])
        ],
    )


def _post_json(url: str, body: bytes) -> bytes:
    req = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        data = resp.read()
        if resp.status >= 300:
            raise FabricError("relay", data.decode(), resp.status)
        return data


def _post_binary(url: str, body: bytes) -> bytes:
    req = Request(
        url,
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        data = resp.read()
        if resp.status >= 300:
            raise FabricError("relay", data.decode(), resp.status)
        return data
