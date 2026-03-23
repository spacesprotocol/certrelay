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


class Fabric:
    def __init__(
        self,
        seeds: Optional[list[str]] = None,
        *,
        dev_mode: bool = False,
        anchor_set_hash: Optional[str] = None,
        prefer_latest: bool = True,
    ):
        self._seeds = seeds or list(DEFAULT_SEEDS)
        self._dev_mode = dev_mode
        self._anchor_set_hash = anchor_set_hash
        self._prefer_latest = prefer_latest
        self._pool = RelayPool()
        self._veritas: Optional[lv.Veritas] = None
        self._zone_cache: dict[str, lv.Zone] = {}
        self._lock = threading.Lock()

    @property
    def relays(self) -> list[str]:
        return self._pool.urls()

    @property
    def anchor_set_hash(self) -> Optional[str]:
        with self._lock:
            return self._anchor_set_hash

    @property
    def veritas(self) -> Optional[lv.Veritas]:
        """The internal Veritas instance for offline verification. None until bootstrap() is called."""
        with self._lock:
            return self._veritas

    # -- Public API --

    def resolve(self, handle: str) -> lv.Zone:
        zones = self.resolve_all([handle])
        zone = next((z for z in zones if z.handle == handle), None)
        if zone is None:
            raise FabricError("decode", f"{handle} not found")
        return zone

    def resolve_all(self, handles: list[str]) -> list[lv.Zone]:
        lookup = lv.Lookup(handles)
        all_zones: list[lv.Zone] = []

        prev_batch: list[str] = []
        batch = lookup.start()
        while batch:
            if batch == prev_batch:
                break
            verified = self._resolve_flat(batch)
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
            verified = self._resolve_flat(batch)
            all_cert_bytes.extend(verified.certificates())
            zones = verified.zones()
            prev_batch = batch
            batch = lookup.advance(zones)

        return lv.create_certificate_chain(handle, all_cert_bytes)

    def bootstrap(self):
        if self._pool.is_empty():
            self._bootstrap_peers()
        if self._veritas is None or self._veritas.newest_anchor() == 0:
            self.update_anchors(self._anchor_set_hash or "")

    def update_anchors(self, hash_str: str = ""):
        if hash_str:
            anchor_set_hash = hash_str
            peers = self._pool.shuffled_urls(4)
        else:
            anchor_set_hash, peers = self._fetch_latest_anchor_set_hash()

        anchors = self._fetch_anchors(anchor_set_hash, peers)

        v = lv.Veritas(anchors)

        with self._lock:
            self._veritas = v
            self._anchor_set_hash = anchor_set_hash

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

    def _resolve_flat(self, handles: list[str]) -> lv.VerifiedMessage:
        by_space: dict[str, list[str]] = {}
        for h in handles:
            space, label = _parse_handle(h)
            by_space.setdefault(space, []).append(label)

        queries = []
        for space, labels in by_space.items():
            q = _Query(space=space, handles=labels)
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
        for q in request.queries:
            ctx.add_request(q.space)
            for h in q.handles:
                if h:
                    ctx.add_request(h + q.space)

        body = request.to_json()
        last_err: Exception = FabricError("no_peers", "no peers available")

        for u in relays:
            try:
                resp_bytes = _post_binary(u + "/query", body)
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

    def _fetch_latest_anchor_set_hash(self) -> tuple[str, list[str]]:
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
    ) -> lv.Anchors:
        expected_root = bytes.fromhex(hash_str)
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

            computed = anchors.compute_anchor_set_hash()
            if computed != expected_root:
                last_err = FabricError("decode", "anchor root mismatch")
                continue

            return anchors

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
