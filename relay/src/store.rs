//! SQLite storage implementation for relay.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::anyhow;
use libveritas::ProvableOption;
use libveritas::Zone;
use libveritas::cert::{Certificate, Witness};
use resolver::ReverseRecord;
use rusqlite::{Connection, OptionalExtension, params};
use spaces_protocol::slabel::SLabel;

const SCHEMA: &str = r#"
-- Handles table: stores handles with their certificate and zone data.
-- Key is the full handle (e.g., "alice@bitcoin" or "@bitcoin").
-- zone_data stores the full zone as borsh for zone.is_better_than comparison.
-- epoch_height is the block height at which the space's commitment was made.
CREATE TABLE IF NOT EXISTS handles (
    handle TEXT PRIMARY KEY,
    space TEXT NOT NULL,
    cert_data BLOB NOT NULL,
    zone_data BLOB NOT NULL,
    epoch_height INTEGER NOT NULL,
    offchain_seq INTEGER NOT NULL DEFAULT 0,
    delegate_offchain_seq INTEGER NOT NULL DEFAULT 0,
    -- Strictly-increasing write sequence (from sync_counter); /sync pages in
    -- this order. Never reused, so a peer's watermark can't miss same-second
    -- writes the way a timestamp cursor could.
    sync_seq INTEGER NOT NULL DEFAULT 0,
    -- sha256 of zone_data: exact-duplicate detection for ingest pre-filtering
    -- (the seq metadata alone can't distinguish a better zone with unchanged
    -- seqs, e.g. a pending->finalized commitment transition).
    zone_hash BLOB NOT NULL DEFAULT x'',
    -- Hex of the zone's current controlling script pubkey, for ownership
    -- discovery (which handles a key controls now — distinct from the
    -- genesis-anchored num_id). '' marks a row the backfill hasn't filled yet.
    controlling_spk TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handles_space ON handles(space);

-- Sync pagination order (see /sync).
CREATE INDEX IF NOT EXISTS idx_handles_sync_seq ON handles(sync_seq);

-- Ownership discovery: find handles currently controlled by a given key.
CREATE INDEX IF NOT EXISTS idx_handles_controlling_spk ON handles(controlling_spk);

-- Singleton write counter feeding handles.sync_seq.
CREATE TABLE IF NOT EXISTS sync_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL
);
INSERT OR IGNORE INTO sync_counter (id, seq) VALUES (1, 0);

-- Per-peer sync progress: the last cursor fully processed from that peer.
-- Cursors are peer-local; never compared across peers.
CREATE TABLE IF NOT EXISTS sync_watermarks (
    peer_url TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Reverse records: maps a numeric identity to its preferred human-readable name.
-- Updated when a message with a Sig record containing a non-empty rev is stored.
CREATE TABLE IF NOT EXISTS reverse (
    num_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Address index: maps (name, addr) to handles for reverse address lookup.
-- Multiple handles can claim the same address.
CREATE TABLE IF NOT EXISTS addrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    addr TEXT NOT NULL,
    handle TEXT NOT NULL,
    rev TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_addrs_lookup ON addrs(name, addr);

-- Eviction deletes addr rows by handle in bulk.
CREATE INDEX IF NOT EXISTS idx_addrs_handle ON addrs(handle);

-- Reverse rows are cleaned up by name when their target handle is evicted.
CREATE INDEX IF NOT EXISTS idx_reverse_name ON reverse(name);

-- Eviction victim ordering within a space (oldest updated first).
CREATE INDEX IF NOT EXISTS idx_handles_space_updated ON handles(space, updated_at);

-- Per-(space, epoch) handle counts: O(1) entitlement accounting for
-- retention. Rows persist at handles = 0 after eviction — an epoch the space
-- was ever seen committing keeps counting toward its entitlement (otherwise
-- eviction would shrink entitlement and spiral).
CREATE TABLE IF NOT EXISTS space_epoch_counts (
    space TEXT NOT NULL,
    epoch_height INTEGER NOT NULL,
    handles INTEGER NOT NULL,
    PRIMARY KEY (space, epoch_height)
);

-- Singleton totals for the handles table payload (rows + blob bytes).
CREATE TABLE IF NOT EXISTS storage_totals (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rows INTEGER NOT NULL,
    bytes INTEGER NOT NULL
);
INSERT OR IGNORE INTO storage_totals (id, rows, bytes) VALUES (1, 0, 0);

-- Keep the accounting true for every insert/replace/delete path (REPLACE
-- fires the delete trigger for the displaced row via recursive_triggers).
CREATE TRIGGER IF NOT EXISTS handles_count_insert AFTER INSERT ON handles BEGIN
    INSERT INTO space_epoch_counts (space, epoch_height, handles)
        VALUES (NEW.space, NEW.epoch_height, 1)
        ON CONFLICT (space, epoch_height) DO UPDATE SET handles = handles + 1;
    UPDATE storage_totals SET rows = rows + 1,
        bytes = bytes + length(NEW.cert_data) + length(NEW.zone_data) WHERE id = 1;
END;

CREATE TRIGGER IF NOT EXISTS handles_count_delete AFTER DELETE ON handles BEGIN
    UPDATE space_epoch_counts SET handles = handles - 1
        WHERE space = OLD.space AND epoch_height = OLD.epoch_height;
    UPDATE storage_totals SET rows = rows - 1,
        bytes = bytes - length(OLD.cert_data) - length(OLD.zone_data) WHERE id = 1;
END;
"#;

/// Result of a bulk store operation.
#[derive(Debug, Default)]
pub struct BulkStoreResult {
    /// Number of handles stored (new or replaced existing).
    pub stored: usize,
    /// Number of handles skipped (existing zone was better).
    pub skipped: usize,
    /// First-inserts skipped by the retention admission gate.
    pub gated: usize,
    /// Handles that were actually stored (not skipped).
    pub stored_handles: Vec<String>,
}

/// A handle record pairing a certificate with its zone.
pub struct HandleRecord {
    pub cert: Certificate,
    pub zone: Zone,
    /// Block height at which the space's commitment was made.
    pub epoch_height: u32,
    /// Records sequence number (extracted from sip7 RecordSet).
    pub offchain_seq: u64,
    /// Delegate records sequence number.
    pub delegate_offchain_seq: u64,
}

/// Lightweight row for hints queries (no blob deserialization).
pub struct HandleHintRow {
    pub handle: String,
    pub epoch_height: u32,
    pub offchain_seq: u64,
    pub delegate_offchain_seq: u64,
    /// sha256 of the stored zone_data blob.
    pub zone_hash: Vec<u8>,
}

/// One match from ownership discovery: a handle currently controlled by the
/// queried key, plus the hint fields a wallet needs to then resolve/restore it.
#[derive(serde::Serialize)]
pub struct DiscoverRow {
    /// Hex controlling spk that matched (so the caller maps it to its query key).
    pub controlling_spk: String,
    pub handle: String,
    pub space: String,
    pub epoch_height: u32,
    pub offchain_seq: u64,
    pub delegate_offchain_seq: u64,
    /// sha256 of the stored zone blob (hex).
    pub zone_hash: String,
}

/// sha256 of a zone blob, matching `handles.zone_hash`.
pub fn zone_hash(zone_data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(zone_data).to_vec()
}

/// Finality ordering for comparing zones — higher is more final.
fn sovereignty_rank(s: libveritas::SovereigntyState) -> u8 {
    use libveritas::SovereigntyState::*;
    match s {
        Sovereign => 2,
        Pending => 1,
        Dependent => 0,
    }
}

/// Whether two zones carry the same on-chain commitment (Exists, equal state
/// root) — so a receipt verified for one still proves the other.
fn same_commitment_root(a: &Zone, b: &Zone) -> bool {
    matches!(
        (&a.commitment, &b.commitment),
        (
            ProvableOption::Exists { value: x },
            ProvableOption::Exists { value: y },
        ) if x.onchain.state_root == y.onchain.state_root
    )
}

/// SQLite-backed store for handles.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::init(Connection::open(path.as_ref())?)
    }

    /// Create an in-memory database (useful for testing).
    pub fn in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        // WAL keeps readers unblocked during writes; busy_timeout prevents
        // immediate SQLITE_BUSY errors; NORMAL sync is durable enough under
        // WAL (data re-syncs from peers in the worst case anyway).
        let _ = conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()));
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // INSERT OR REPLACE must fire the delete trigger for the displaced
        // row, or the storage accounting drifts on every update.
        conn.pragma_update(None, "recursive_triggers", true)?;

        // Column migration must run before SCHEMA: the sync_seq index in
        // SCHEMA would fail against a pre-sync handles table.
        Self::migrate_columns(&conn)?;
        conn.execute_batch(SCHEMA)?;
        Self::backfill_sync(&conn)?;
        Self::backfill_controlling_spk(&conn)?;
        Self::backfill_storage(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Add columns introduced after the first production deploy to an
    /// existing handles table (no-op for fresh or already-migrated DBs).
    fn migrate_columns(conn: &Connection) -> anyhow::Result<()> {
        let has_handles: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'handles'",
            [],
            |r| r.get::<_, i64>(0).map(|n| n > 0),
        )?;
        if !has_handles {
            return Ok(());
        }

        let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('handles')")?;
        let columns: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;

        if !columns.iter().any(|c| c == "sync_seq") {
            conn.execute(
                "ALTER TABLE handles ADD COLUMN sync_seq INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !columns.iter().any(|c| c == "zone_hash") {
            conn.execute(
                "ALTER TABLE handles ADD COLUMN zone_hash BLOB NOT NULL DEFAULT x''",
                [],
            )?;
        }
        if !columns.iter().any(|c| c == "controlling_spk") {
            conn.execute(
                "ALTER TABLE handles ADD COLUMN controlling_spk TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        Ok(())
    }

    /// Assign sync sequence numbers and zone hashes to pre-migration rows.
    ///
    /// New rows always get `sync_seq >= 1` at insert, so `sync_seq = 0`
    /// identifies exactly the legacy rows; the backfill is idempotent and
    /// crash-safe (single transaction).
    fn backfill_sync(conn: &Connection) -> anyhow::Result<()> {
        // Chunked so the migration never loads the whole table (with zone
        // blobs) into memory. sync_seq = 0 marks unmigrated rows, so each
        // chunk is one transaction and a crash resumes where it left off.
        const CHUNK: usize = 1000;
        let mut migrated = 0usize;
        loop {
            let chunk: Vec<(String, Vec<u8>)> = {
                let mut stmt = conn.prepare(
                    "SELECT handle, zone_data FROM handles WHERE sync_seq = 0
                     ORDER BY updated_at, handle LIMIT ?",
                )?;
                let rows = stmt.query_map(params![CHUNK as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            if chunk.is_empty() {
                break;
            }

            let tx = conn.unchecked_transaction()?;
            let base: i64 = tx.query_row("SELECT seq FROM sync_counter WHERE id = 1", [], |r| {
                r.get(0)
            })?;
            for (i, (handle, zone_data)) in chunk.iter().enumerate() {
                tx.execute(
                    "UPDATE handles SET sync_seq = ?, zone_hash = ? WHERE handle = ?",
                    params![base + 1 + i as i64, zone_hash(zone_data), handle],
                )?;
            }
            tx.execute(
                "UPDATE sync_counter SET seq = ? WHERE id = 1",
                params![base + chunk.len() as i64],
            )?;
            tx.commit()?;
            migrated += chunk.len();
        }
        if migrated > 0 {
            tracing::info!("migrated {} pre-sync handle rows", migrated);
        }
        Ok(())
    }

    /// Backfill `controlling_spk` for rows predating the column by decoding each
    /// stored zone's `script_pubkey`. New rows set it at insert, so `''` marks
    /// exactly the legacy rows. Idempotent and crash-resumable: every processed
    /// row ends non-empty (a decode failure gets the `-` sentinel, which no real
    /// spk-hex query matches), so the `''` selection strictly shrinks.
    fn backfill_controlling_spk(conn: &Connection) -> anyhow::Result<()> {
        const CHUNK: usize = 1000;
        let mut migrated = 0usize;
        loop {
            let chunk: Vec<(String, Vec<u8>)> = {
                let mut stmt = conn.prepare(
                    "SELECT handle, zone_data FROM handles WHERE controlling_spk = ''
                     ORDER BY handle LIMIT ?",
                )?;
                let rows = stmt.query_map(params![CHUNK as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            if chunk.is_empty() {
                break;
            }

            let tx = conn.unchecked_transaction()?;
            for (handle, zone_data) in &chunk {
                let spk = borsh::from_slice::<Zone>(zone_data)
                    .map(|z| hex::encode(z.script_pubkey.as_bytes()))
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "-".to_string());
                tx.execute(
                    "UPDATE handles SET controlling_spk = ? WHERE handle = ?",
                    params![spk, handle],
                )?;
            }
            tx.commit()?;
            migrated += chunk.len();
        }
        if migrated > 0 {
            tracing::info!("backfilled controlling_spk for {} handle rows", migrated);
        }
        Ok(())
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // =========================================================================
    // Handles
    // =========================================================================

    /// Update handles in bulk. Uses `zone.is_better_than` to decide whether
    /// each incoming record should replace the existing one.
    pub fn update_handles(&self, updates: &[HandleRecord]) -> anyhow::Result<BulkStoreResult> {
        if updates.is_empty() {
            return Ok(BulkStoreResult::default());
        }

        struct Prepared {
            handle: String,
            space: String,
            cert_data: Vec<u8>,
            zone_data: Vec<u8>,
            epoch_height: u32,
            offchain_seq: u64,
            delegate_offchain_seq: u64,
            /// Hex of the zone's current controlling script pubkey (ownership
            /// discovery index).
            controlling_spk: String,
            /// Keep the existing stored cert_data instead of this update's cert
            /// (its receipt was omitted; see the preservation note below).
            preserve_cert: bool,
        }

        let mut entries = Vec::with_capacity(updates.len());
        for update in updates {
            let handle = update.cert.subject.to_string();
            let space = update
                .cert
                .subject
                .space()
                .ok_or_else(|| anyhow!("certificate subject missing space"))?
                .to_string();
            let cert_data = borsh::to_vec(&update.cert)
                .map_err(|e| anyhow!("failed to serialize certificate: {}", e))?;
            let zone_data = borsh::to_vec(&update.zone)
                .map_err(|e| anyhow!("failed to serialize zone: {}", e))?;
            let controlling_spk = hex::encode(update.zone.script_pubkey.as_bytes());
            entries.push(Prepared {
                handle,
                space,
                cert_data,
                zone_data,
                epoch_height: update.epoch_height,
                offchain_seq: update.offchain_seq,
                delegate_offchain_seq: update.delegate_offchain_seq,
                controlling_spk,
                preserve_cert: false,
            });
        }

        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        // Bulk SELECT: get existing zones for comparison
        let handles: Vec<&str> = entries.iter().map(|e| e.handle.as_str()).collect();
        let existing_zones = Self::get_zones_inner(&conn, &handles)?;

        // seq is a unix-seconds timestamp; reject records claiming a seq more than
        // 6h in the future (accidental far-future clocks or deliberate freshness
        // pinning).
        let max_seq = (now + 6 * 3600) as u64;

        // Filter to entries where the incoming zone is better (or new), and
        // preserve owner records across a commitment upgrade (see below).
        let to_store: Vec<Prepared> = entries
            .into_iter()
            .zip(updates.iter())
            .filter_map(|(mut e, update)| {
                if e.offchain_seq > max_seq || e.delegate_offchain_seq > max_seq {
                    tracing::warn!(
                        "{}: rejecting update, seq {} exceeds max {} (>6h in future)",
                        e.handle,
                        e.offchain_seq.max(e.delegate_offchain_seq),
                        max_seq
                    );
                    return None;
                }

                let existing = match existing_zones.get(e.handle.as_str()) {
                    None => return Some(e), // new handle, nothing to preserve
                    Some(existing) => {
                        // A temp->final finalization (or a re-proof after a newer
                        // commitment) carries a fresher anchor but often EMPTY owner
                        // records. For a sub-handle both zones have Unknown
                        // commitment, so is_better_than falls to the records check
                        // and rejects the empty-records final BEFORE the anchor
                        // tiebreaker — leaving the relay serving a stale temp that no
                        // longer verifies against the tip. Accept a strictly fresher
                        // proof from the same key as long as it doesn't downgrade
                        // finality; the owner's records are preserved by the merge
                        // below. Incoming certs are already verified against current
                        // anchors, so a higher anchor is genuine fresher chain truth.
                        let fresher_proof = update.zone.script_pubkey == existing.script_pubkey
                            && update.zone.anchor > existing.anchor
                            && sovereignty_rank(update.zone.sovereignty)
                                >= sovereignty_rank(existing.sovereignty);
                        if !fresher_proof && !update.zone.is_better_than(existing).unwrap_or(false)
                        {
                            return None; // stored zone is as good or better
                        }
                        existing
                    }
                };

                // A commitment upgrade (e.g. a temp -> final cert) can arrive
                // carrying empty or stale owner records. `is_better_than` picks
                // it on commitment height alone, which would silently drop the
                // owner's records. Keep them when the same key still controls the
                // handle (script_pubkey unchanged) and the stored records are
                // fresher — they remain valid under the new commitment. A genuine
                // owner update (higher records seq) or a key transfer (different
                // script_pubkey) is left untouched.
                if existing.script_pubkey == update.zone.script_pubkey
                    && !existing.records.is_empty()
                    && (update.zone.records.is_empty()
                        || existing.records.seq().unwrap_or(0)
                            > update.zone.records.seq().unwrap_or(0))
                {
                    let mut merged = update.zone.clone();
                    merged.records = existing.records.clone();
                    match borsh::to_vec(&merged) {
                        Ok(bytes) => {
                            e.zone_data = bytes;
                            e.offchain_seq = merged.records.seq().unwrap_or(0);
                        }
                        // Fall back to storing the incoming zone unmerged rather
                        // than dropping the update entirely.
                        Err(err) => {
                            tracing::warn!("{}: merged-zone re-serialize failed: {}", e.handle, err)
                        }
                    }
                }

                // Preserve the ZK receipt: a root cert re-sent for the same
                // commitment often omits it (the sender assumes we still hold
                // it), which would leave us serving a receipt-less cert that no
                // sub-handle can verify against the tip. Keep our existing
                // cert_data (the zone still updates to the fresher anchor above;
                // only the cert, and its receipt, is retained). Same commitment
                // root is the safe condition: a receipt-less cert only reaches
                // here if we already verified that commitment. The insert reads
                // the existing cert_data in-place, so no extra fetch is needed.
                if matches!(&update.cert.witness, Witness::Root { receipt: None })
                    && same_commitment_root(&update.zone, existing)
                {
                    e.preserve_cert = true;
                }

                Some(e)
            })
            .collect();

        let skipped = updates.len() - to_store.len();

        if to_store.is_empty() {
            return Ok(BulkStoreResult {
                stored: 0,
                skipped,
                gated: 0,
                stored_handles: vec![],
            });
        }

        // Counter bump + row inserts commit atomically: a crash can't leave
        // rows claiming sequence numbers the counter doesn't cover.
        let tx = conn.unchecked_transaction()?;
        let seq_base: i64 = tx.query_row("SELECT seq FROM sync_counter WHERE id = 1", [], |r| {
            r.get(0)
        })?;
        tx.execute(
            "UPDATE sync_counter SET seq = ? WHERE id = 1",
            params![seq_base + to_store.len() as i64],
        )?;

        // Bulk INSERT. For preserve_cert rows the cert_data column reads the
        // existing stored value in-place (keeping its ZK receipt) rather than
        // taking this update's receipt-less cert; the zone still updates. The
        // subquery runs before REPLACE deletes the old row, and since the value
        // is unchanged the storage-byte trigger nets out on cert_data.
        let placeholders: Vec<String> = to_store
            .iter()
            .map(|e| {
                if e.preserve_cert {
                    "(?, ?, (SELECT cert_data FROM handles WHERE handle = ?), ?, ?, ?, ?, ?, ?, ?, ?)"
                        .to_string()
                } else {
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string()
                }
            })
            .collect();
        let query = format!(
            "INSERT OR REPLACE INTO handles (handle, space, cert_data, zone_data, epoch_height, offchain_seq, delegate_offchain_seq, sync_seq, zone_hash, controlling_spk, updated_at) VALUES {}",
            placeholders.join(", ")
        );

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::with_capacity(to_store.len() * 11);
        for (i, e) in to_store.iter().enumerate() {
            params.push(Box::new(e.handle.clone()));
            params.push(Box::new(e.space.clone()));
            // cert_data: bind the handle for the SELECT subquery when preserving,
            // otherwise this update's cert bytes.
            if e.preserve_cert {
                params.push(Box::new(e.handle.clone()));
            } else {
                params.push(Box::new(e.cert_data.clone()));
            }
            params.push(Box::new(e.zone_data.clone()));
            params.push(Box::new(e.epoch_height));
            params.push(Box::new(e.offchain_seq as i64));
            params.push(Box::new(e.delegate_offchain_seq as i64));
            params.push(Box::new(seq_base + 1 + i as i64));
            params.push(Box::new(zone_hash(&e.zone_data)));
            params.push(Box::new(e.controlling_spk.clone()));
            params.push(Box::new(now));
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        tx.execute(&query, param_refs.as_slice())?;
        tx.commit()?;

        let stored_handles = to_store.iter().map(|e| e.handle.clone()).collect();
        Ok(BulkStoreResult {
            stored: to_store.len(),
            skipped,
            gated: 0,
            stored_handles,
        })
    }

    /// Rebuild the storage accounting tables from a full scan when they are
    /// empty but handles exist (upgrade of a pre-retention database).
    /// Idempotent: a fresh or already-accounted DB is a no-op.
    fn backfill_storage(conn: &Connection) -> anyhow::Result<()> {
        let (acct_rows,): (i64,) =
            conn.query_row("SELECT rows FROM storage_totals WHERE id = 1", [], |r| {
                Ok((r.get(0)?,))
            })?;
        if acct_rows != 0 {
            return Ok(());
        }
        let actual: i64 = conn.query_row("SELECT COUNT(*) FROM handles", [], |r| r.get(0))?;
        if actual == 0 {
            return Ok(());
        }

        tracing::info!("backfilling storage accounting for {} handle rows", actual);
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO space_epoch_counts (space, epoch_height, handles)
             SELECT space, epoch_height, COUNT(*) FROM handles GROUP BY space, epoch_height",
            [],
        )?;
        tx.execute(
            "UPDATE storage_totals SET
                rows = (SELECT COUNT(*) FROM handles),
                bytes = (SELECT COALESCE(SUM(length(cert_data) + length(zone_data)), 0) FROM handles)
             WHERE id = 1",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    // =========================================================================
    // Retention accounting
    // =========================================================================

    /// Current handle-table payload totals: (rows, bytes). O(1).
    pub fn storage_totals(&self) -> anyhow::Result<(u64, u64)> {
        let conn = self.conn.lock().unwrap();
        let (rows, bytes): (i64, i64) = conn.query_row(
            "SELECT rows, bytes FROM storage_totals WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((rows.max(0) as u64, bytes.max(0) as u64))
    }

    /// One space's stored handle count and the number of epochs it was ever
    /// seen committing (empty buckets still count toward entitlement).
    pub fn space_usage(&self, space: &str) -> anyhow::Result<(u64, u64)> {
        let conn = self.conn.lock().unwrap();
        let (stored, epochs): (i64, i64) = conn.query_row(
            "SELECT COALESCE(SUM(handles), 0), COUNT(*) FROM space_epoch_counts WHERE space = ?",
            params![space],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((stored.max(0) as u64, epochs.max(0) as u64))
    }

    /// Usage for every space with stored handles: (space, stored, epochs).
    /// Scans the counts table (spaces x epochs rows — small), not handles.
    pub fn space_usage_all(&self) -> anyhow::Result<Vec<(String, u64, u64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT space, SUM(handles), COUNT(*) FROM space_epoch_counts
             GROUP BY space HAVING SUM(handles) > 0",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?.max(0) as u64,
                r.get::<_, i64>(2)?.max(0) as u64,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// The oldest-updated handles of a space (eviction candidates). The root
    /// row (`handle = space`) is never a candidate: without it every
    /// remaining sub-handle becomes unresolvable and unverifiable, and the
    /// space cannot recover (peers won't re-serve a row below our watermark).
    pub fn eviction_candidates(&self, space: &str, limit: usize) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT handle FROM handles WHERE space = ?1 AND handle != ?1
             ORDER BY updated_at ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![space, limit as i64], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Delete handles (and their address-index and reverse rows) in one
    /// transaction. The accounting triggers keep counts and totals true.
    pub fn delete_handles(&self, handles: &[String]) -> anyhow::Result<usize> {
        if handles.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let placeholders: Vec<&str> = handles.iter().map(|_| "?").collect();
        let params: Vec<&dyn rusqlite::ToSql> =
            handles.iter().map(|h| h as &dyn rusqlite::ToSql).collect();

        // Reverse rows pointing at deleted handles would resolve to nothing.
        // Extract the exact (num_id, rev name) pairs from the zones being
        // deleted — mirroring how set_revs created them — so handles with a
        // Sig but no Addr records are covered, and reverse rows of other
        // num_ids sharing a display name are never touched.
        {
            use libveritas::sip7::SIG_PRIMARY_ZONE;
            let mut stmt = tx.prepare(&format!(
                "SELECT zone_data FROM handles WHERE handle IN ({})",
                placeholders.join(", ")
            ))?;
            let blobs = stmt.query_map(params.as_slice(), |r| r.get::<_, Vec<u8>>(0))?;
            for blob in blobs {
                let Ok(zone) = borsh::from_slice::<Zone>(&blob?) else {
                    continue;
                };
                if let Some(sig) = zone.records.sig()
                    && sig.flags & SIG_PRIMARY_ZONE == SIG_PRIMARY_ZONE
                    && let Some(num_id) = &zone.num_id
                {
                    tx.execute(
                        "DELETE FROM reverse WHERE num_id = ? AND name = ?",
                        params![num_id.to_string(), sig.handle.to_string()],
                    )?;
                }
            }
        }
        tx.execute(
            &format!(
                "DELETE FROM addrs WHERE handle IN ({})",
                placeholders.join(", ")
            ),
            params.as_slice(),
        )?;
        let deleted = tx.execute(
            &format!(
                "DELETE FROM handles WHERE handle IN ({})",
                placeholders.join(", ")
            ),
            params.as_slice(),
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Test helper: rewrite a handle's row position to the end of the sync
    /// stream (simulates a root republished after its sub-handles).
    #[cfg(any(test, feature = "testutil"))]
    pub fn bump_sync_seq(&self, handle: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let next: i64 = tx.query_row("SELECT seq + 1 FROM sync_counter WHERE id = 1", [], |r| {
            r.get(0)
        })?;
        tx.execute(
            "UPDATE handles SET sync_seq = ? WHERE handle = ?",
            params![next, handle],
        )?;
        tx.execute(
            "UPDATE sync_counter SET seq = ? WHERE id = 1",
            params![next],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Get a single handle record.
    pub fn get_handle(&self, handle: &str) -> anyhow::Result<Option<HandleRecord>> {
        let conn = self.conn.lock().unwrap();

        type HandleRow = (Vec<u8>, Vec<u8>, u32, i64, i64);
        let row: Option<HandleRow> = conn
            .query_row(
                "SELECT cert_data, zone_data, epoch_height, offchain_seq, delegate_offchain_seq FROM handles WHERE handle = ?",
                params![handle],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;

        match row {
            Some((cert_bytes, zone_bytes, epoch_height, offchain_seq, delegate_offchain_seq)) => {
                let cert: Certificate = borsh::from_slice(&cert_bytes)
                    .map_err(|e| anyhow!("failed to deserialize certificate: {}", e))?;
                let zone: Zone = borsh::from_slice(&zone_bytes)
                    .map_err(|e| anyhow!("failed to deserialize zone: {}", e))?;
                Ok(Some(HandleRecord {
                    cert,
                    zone,
                    epoch_height,
                    offchain_seq: offchain_seq as u64,
                    delegate_offchain_seq: delegate_offchain_seq as u64,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get multiple handle records in bulk.
    pub fn get_handles(&self, handles: &[&str]) -> anyhow::Result<Vec<HandleRecord>> {
        if handles.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();

        let placeholders: Vec<&str> = handles.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT cert_data, zone_data, epoch_height, offchain_seq, delegate_offchain_seq FROM handles WHERE handle IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            handles.iter().map(|h| h as &dyn rusqlite::ToSql).collect();

        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (cert_bytes, zone_bytes, epoch_height, offchain_seq, delegate_offchain_seq) = row?;
            let cert: Certificate = borsh::from_slice(&cert_bytes)
                .map_err(|e| anyhow!("failed to deserialize certificate: {}", e))?;
            let zone: Zone = borsh::from_slice(&zone_bytes)
                .map_err(|e| anyhow!("failed to deserialize zone: {}", e))?;
            results.push(HandleRecord {
                cert,
                zone,
                epoch_height,
                offchain_seq: offchain_seq as u64,
                delegate_offchain_seq: delegate_offchain_seq as u64,
            });
        }

        Ok(results)
    }

    /// Get zones for the given root handles (by space label).
    /// Reads the zone_data from the root handle's row (single-label handle).
    pub fn get_zones(&self, spaces: &[&SLabel]) -> anyhow::Result<Vec<Zone>> {
        let conn = self.conn.lock().unwrap();
        let mut zones = Vec::new();

        for space in spaces {
            let handle_str = space.to_string();
            let zone_data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT zone_data FROM handles WHERE handle = ?",
                    params![handle_str],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(data) = zone_data {
                let zone: Zone = borsh::from_slice(&data)
                    .map_err(|e| anyhow!("failed to deserialize zone: {}", e))?;
                zones.push(zone);
            }
        }

        Ok(zones)
    }

    /// Lightweight hints query — returns only handle, epoch_height, and offchain_seq.
    /// No blob deserialization.
    pub fn get_handle_hints(&self, handles: &[&str]) -> anyhow::Result<Vec<HandleHintRow>> {
        if handles.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().unwrap();

        let placeholders: Vec<&str> = handles.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT handle, epoch_height, offchain_seq, delegate_offchain_seq, zone_hash FROM handles WHERE handle IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            handles.iter().map(|h| h as &dyn rusqlite::ToSql).collect();

        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(HandleHintRow {
                handle: row.get(0)?,
                epoch_height: row.get(1)?,
                offchain_seq: row.get::<_, i64>(2)? as u64,
                delegate_offchain_seq: row.get::<_, i64>(3)? as u64,
                zone_hash: row.get(4)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // =========================================================================
    // Sync
    // =========================================================================

    /// Read a page of handle rows after `cursor` in `sync_seq` order.
    ///
    /// `limit` bounds the row count; `max_bytes` additionally stops the page
    /// once the accumulated blob size exceeds it (always returns at least one
    /// row if any exist past the cursor).
    pub fn sync_page(
        &self,
        cursor: Option<resolver::SyncCursor>,
        limit: usize,
        max_bytes: usize,
    ) -> anyhow::Result<resolver::SyncPage> {
        let conn = self.conn.lock().unwrap();
        let after = cursor.map(|c| c.0 as i64).unwrap_or(0);

        let mut stmt = conn.prepare(
            "SELECT handle, epoch_height, offchain_seq, delegate_offchain_seq, cert_data, zone_data, sync_seq
             FROM handles
             WHERE sync_seq > ?1
             ORDER BY sync_seq
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![after, limit as i64], |row| {
            Ok((
                resolver::SyncRecord {
                    handle: row.get(0)?,
                    epoch_height: row.get(1)?,
                    seq: row.get::<_, i64>(2)? as u64,
                    delegate_seq: row.get::<_, i64>(3)? as u64,
                    cert: row.get(4)?,
                    zone: row.get(5)?,
                },
                row.get::<_, i64>(6)?,
            ))
        })?;

        let mut main: Vec<(resolver::SyncRecord, i64)> = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let (record, sync_seq) = row?;
            bytes += record.cert.len() + record.zone.len();
            main.push((record, sync_seq));
            if bytes > max_bytes {
                break;
            }
        }
        drop(stmt);

        // A root republished after its sub-handles carries a higher sync_seq,
        // so a bootstrapping peer would reach the subs before the root and be
        // unable to verify them. Append such roots (they land beyond this
        // page) as extra records — the peer's duplicate pre-filter drops them
        // again when their own row arrives in cursor order. next_cursor is
        // unaffected: it tracks only the main selection.
        let last_seq = main.last().map(|(_, s)| *s).unwrap_or(after);
        let sub_spaces: std::collections::HashSet<String> = main
            .iter()
            .filter(|(r, _)| r.handle != r.space_name())
            .map(|(r, _)| r.space_name().to_string())
            .collect();
        let mut roots: HashMap<String, resolver::SyncRecord> = HashMap::new();
        if !sub_spaces.is_empty() {
            let space_list: Vec<&str> = sub_spaces.iter().map(|s| s.as_str()).collect();
            let placeholders: Vec<&str> = space_list.iter().map(|_| "?").collect();
            let query = format!(
                "SELECT handle, epoch_height, offchain_seq, delegate_offchain_seq, cert_data, zone_data
                 FROM handles
                 WHERE handle IN ({}) AND handle = space AND sync_seq > ?",
                placeholders.join(", ")
            );
            let mut stmt = conn.prepare(&query)?;
            let mut params: Vec<&dyn rusqlite::ToSql> = space_list
                .iter()
                .map(|s| s as &dyn rusqlite::ToSql)
                .collect();
            params.push(&last_seq);
            let found = stmt.query_map(params.as_slice(), |row| {
                Ok(resolver::SyncRecord {
                    handle: row.get(0)?,
                    epoch_height: row.get(1)?,
                    seq: row.get::<_, i64>(2)? as u64,
                    delegate_seq: row.get::<_, i64>(3)? as u64,
                    cert: row.get(4)?,
                    zone: row.get(5)?,
                })
            })?;
            for root in found {
                let root = root?;
                roots.insert(root.handle.clone(), root);
            }
        }

        // Hard combined cap: appended roots (which can carry ~250 KB ZK
        // receipts) count against the page too. If they don't fit, shrink the
        // main selection from the tail — dropped rows are simply re-served
        // next page — until rows + their required roots fit. One row plus one
        // root always fits (both bounded by the message size cap), so the
        // page always makes progress and can never exceed what pullers accept.
        let hard_cap = max_bytes.saturating_mul(2);
        let record_bytes = |r: &resolver::SyncRecord| r.cert.len() + r.zone.len();
        let total = |main: &[(resolver::SyncRecord, i64)],
                     roots: &HashMap<String, resolver::SyncRecord>| {
            let needed: std::collections::HashSet<&str> = main
                .iter()
                .filter(|(r, _)| r.handle != r.space_name())
                .map(|(r, _)| r.space_name())
                .collect();
            main.iter().map(|(r, _)| record_bytes(r)).sum::<usize>()
                + roots
                    .values()
                    .filter(|r| needed.contains(r.handle.as_str()))
                    .map(record_bytes)
                    .sum::<usize>()
        };
        while main.len() > 1 && total(&main, &roots) > hard_cap {
            let Some((popped, _)) = main.pop() else {
                break;
            };
            // A popped root may still be needed by its sub-handles earlier in
            // the page — re-home it into the roots map (it only counts toward
            // the cap, and only ships, while such a sub survives). Discarding
            // it would send orphaned subs a bootstrapping peer cannot verify.
            if popped.handle == popped.space_name() {
                roots.entry(popped.handle.clone()).or_insert(popped);
            }
        }

        let mut page = resolver::SyncPage::default();
        let needed: std::collections::HashSet<String> = main
            .iter()
            .filter(|(r, _)| r.handle != r.space_name())
            .map(|(r, _)| r.space_name().to_string())
            .collect();
        for (record, sync_seq) in main {
            page.next_cursor = Some(resolver::SyncCursor(sync_seq as u64).to_string());
            page.records.push(record);
        }
        for (handle, root) in roots {
            if needed.contains(handle.as_str()) {
                page.records.push(root);
            }
        }
        Ok(page)
    }

    /// Row count and newest cursor, for /sync/summary.
    ///
    /// The cursor is the persistent write counter, not MAX(sync_seq): the
    /// counter never regresses when the highest-seq rows are evicted, so
    /// peers cannot misread eviction as a cursor-space reset (which would
    /// trigger a full re-sync). Pullers that reach a region with no rows
    /// left get an empty page and catch their watermark up.
    pub fn sync_summary(&self) -> anyhow::Result<resolver::SyncSummary> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM handles", [], |r| r.get(0))?;
        let counter: i64 =
            conn.query_row("SELECT seq FROM sync_counter WHERE id = 1", [], |r| {
                r.get(0)
            })?;
        Ok(resolver::SyncSummary {
            count: count as u64,
            latest_cursor: (counter > 0).then(|| resolver::SyncCursor(counter as u64).to_string()),
        })
    }

    /// Last fully-processed sync cursor for a peer.
    pub fn get_watermark(&self, peer_url: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cursor FROM sync_watermarks WHERE peer_url = ?",
            params![peer_url],
            |r| r.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// Persist the sync cursor for a peer.
    pub fn set_watermark(&self, peer_url: &str, cursor: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sync_watermarks (peer_url, cursor, updated_at) VALUES (?, ?, ?)",
            params![peer_url, cursor, Self::now()],
        )?;
        Ok(())
    }

    /// Get existing zones for handles (used internally for is_better_than comparison).
    fn get_zones_inner(
        conn: &Connection,
        handles: &[&str],
    ) -> anyhow::Result<HashMap<String, Zone>> {
        let mut result = HashMap::new();
        if handles.is_empty() {
            return Ok(result);
        }

        let placeholders: Vec<&str> = handles.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT handle, zone_data FROM handles WHERE handle IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            handles.iter().map(|h| h as &dyn rusqlite::ToSql).collect();

        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;

        for row in rows {
            let (handle, zone_bytes) = row?;
            let zone: Zone = borsh::from_slice(&zone_bytes)
                .map_err(|e| anyhow!("failed to deserialize zone: {}", e))?;
            result.insert(handle, zone);
        }

        Ok(result)
    }

    // =========================================================================
    // Reverse records
    // =========================================================================

    /// Bulk store reverse mappings from num_id to human-readable name.
    pub fn set_revs(&self, entries: &[(&str, &str)]) -> anyhow::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        let tx = conn.unchecked_transaction()?;
        for (num_id, name) in entries {
            tx.execute(
                "INSERT OR REPLACE INTO reverse (num_id, name, updated_at) VALUES (?, ?, ?)",
                params![num_id, name, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Look up reverse records for the given num IDs.
    pub fn get_revs(&self, num_ids: &[&str]) -> anyhow::Result<Vec<ReverseRecord>> {
        if num_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        let placeholders: Vec<&str> = num_ids.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT num_id, name FROM reverse WHERE num_id IN ({})",
            placeholders.join(", ")
        );
        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> = num_ids
            .iter()
            .map(|id| id as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(ReverseRecord {
                id: row.get(0)?,
                name: row.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Ownership discovery: handles currently controlled by any of these spks
    /// (hex). One key can control several handles, so each query spk may match
    /// multiple rows. Reflects the controller as of the last stored zone.
    pub fn discover_by_controlling_spk(&self, spks: &[&str]) -> anyhow::Result<Vec<DiscoverRow>> {
        if spks.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        let placeholders: Vec<&str> = spks.iter().map(|_| "?").collect();
        let query = format!(
            "SELECT controlling_spk, handle, space, epoch_height, offchain_seq, delegate_offchain_seq, zone_hash
             FROM handles WHERE controlling_spk IN ({})",
            placeholders.join(", ")
        );
        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            spks.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(DiscoverRow {
                controlling_spk: row.get(0)?,
                handle: row.get(1)?,
                space: row.get(2)?,
                epoch_height: row.get(3)?,
                offchain_seq: row.get::<_, i64>(4)? as u64,
                delegate_offchain_seq: row.get::<_, i64>(5)? as u64,
                zone_hash: hex::encode(row.get::<_, Vec<u8>>(6)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // =========================================================================
    // Address index
    // =========================================================================

    /// Update address index for a handle. Deletes old entries by canonical handle and inserts new ones.
    /// `handle` is the canonical name (used for delete), `rev` is the human-readable name.
    /// `entries` is a list of `(addr_name, addr_value)` pairs, e.g. `("btc", "bc1q...")`.
    pub fn set_addrs(
        &self,
        handle: &str,
        rev: &str,
        entries: &[(&str, &str)],
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM addrs WHERE handle = ?", params![handle])?;
        let now = Self::now();
        for (name, addr) in entries {
            tx.execute(
                "INSERT INTO addrs (name, addr, handle, rev, updated_at) VALUES (?, ?, ?, ?, ?)",
                params![name, addr, handle, rev, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Look up handles by address. Returns (canonical_handle, rev_name) pairs.
    pub fn get_addrs(&self, name: &str, addr: &str) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT handle, rev FROM addrs WHERE name = ? AND addr = ?")?;
        let rows = stmt.query_map(params![name, addr], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
impl SqliteStore {
    /// Test-only: insert/replace a handle with a `zone_hash` derived from
    /// `zone_data`, so version/ETag tests see realistic hashes.
    pub fn test_insert(&self, handle: &str, space: &str, epoch: i64, zone_data: &[u8]) {
        let zh = zone_hash(zone_data);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO handles \
             (handle, space, cert_data, zone_data, epoch_height, zone_hash, updated_at) \
             VALUES (?,?,x'01',?,?,?,100)",
            params![handle, space, zone_data, epoch, zh],
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening a database created before the sync schema (production relays
    /// with real handle rows) must add the new columns, backfill sync_seq in
    /// (updated_at, handle) order, hash the zones, and seed the counter.
    #[test]
    fn test_migrates_pre_sync_database() {
        let path = std::env::temp_dir().join(format!(
            "certrelay-migration-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        // Exact pre-sync production schema
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE handles (
                    handle TEXT PRIMARY KEY,
                    space TEXT NOT NULL,
                    cert_data BLOB NOT NULL,
                    zone_data BLOB NOT NULL,
                    epoch_height INTEGER NOT NULL,
                    offchain_seq INTEGER NOT NULL DEFAULT 0,
                    delegate_offchain_seq INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX idx_handles_space ON handles(space);
                CREATE TABLE reverse (
                    num_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )
            .unwrap();
            for (handle, ts) in [
                ("@bitcoin", 100),
                ("alice@bitcoin", 200),
                ("bob@bitcoin", 150),
            ] {
                conn.execute(
                    "INSERT INTO handles (handle, space, cert_data, zone_data, epoch_height, offchain_seq, delegate_offchain_seq, updated_at)
                     VALUES (?, '@bitcoin', x'01', ?, 870000, 5, 0, ?)",
                    params![handle, handle.as_bytes(), ts],
                )
                .unwrap();
            }
        }

        let store = SqliteStore::open(&path).unwrap();

        // Backfill covers every row, ordered by (updated_at, handle):
        // @bitcoin (100) -> 1, bob (150) -> 2, alice (200) -> 3
        let summary = store.sync_summary().unwrap();
        assert_eq!(summary.count, 3);
        assert_eq!(summary.latest_cursor.as_deref(), Some("3"));

        let page = store.sync_page(None, 10, usize::MAX).unwrap();
        let order: Vec<&str> = page.records.iter().map(|r| r.handle.as_str()).collect();
        assert_eq!(order, ["@bitcoin", "bob@bitcoin", "alice@bitcoin"]);

        // zone_hash matches the stored blob; hint metadata survived
        let hints = store.get_handle_hints(&["alice@bitcoin"]).unwrap();
        assert_eq!(hints[0].zone_hash, zone_hash(b"alice@bitcoin"));
        assert_eq!(hints[0].offchain_seq, 5);
        assert_eq!(hints[0].epoch_height, 870000);

        // New writes continue after the backfilled sequence range
        {
            let conn = store.conn.lock().unwrap();
            let seq: i64 = conn
                .query_row("SELECT seq FROM sync_counter WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(seq, 3);
        }

        // Storage accounting was backfilled from the legacy rows
        let (rows, bytes) = store.storage_totals().unwrap();
        assert_eq!(rows, 3);
        assert!(bytes > 0, "backfilled bytes should cover the blobs");
        assert_eq!(store.space_usage("@bitcoin").unwrap(), (3, 1));

        // Re-opening must not re-migrate (idempotent)
        drop(store);
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            store.sync_summary().unwrap().latest_cursor.as_deref(),
            Some("3")
        );
        assert_eq!(store.storage_totals().unwrap().0, 3, "no double backfill");

        let _ = std::fs::remove_file(&path);
    }

    fn raw_insert(store: &SqliteStore, handle: &str, space: &str, epoch: i64, blob: &[u8]) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO handles (handle, space, cert_data, zone_data, epoch_height, updated_at)
             VALUES (?, ?, x'01', ?, ?, 100)",
            params![handle, space, blob, epoch],
        )
        .unwrap();
    }

    /// Triggers keep storage accounting true across insert, replace, and
    /// delete — including REPLACE displacing an old row (recursive_triggers).
    #[test]
    fn test_storage_accounting_triggers() {
        let store = SqliteStore::in_memory().unwrap();
        assert_eq!(store.storage_totals().unwrap(), (0, 0));

        raw_insert(&store, "@a", "@a", 100, &[0u8; 10]);
        raw_insert(&store, "x@a", "@a", 100, &[0u8; 20]);
        raw_insert(&store, "y@a", "@a", 200, &[0u8; 30]);
        // cert x'01' = 1 byte each
        assert_eq!(store.storage_totals().unwrap(), (3, 63));
        assert_eq!(store.space_usage("@a").unwrap(), (3, 2));

        // REPLACE: old row's bytes must be subtracted, count unchanged
        raw_insert(&store, "x@a", "@a", 100, &[0u8; 50]);
        assert_eq!(store.storage_totals().unwrap(), (3, 93));
        assert_eq!(store.space_usage("@a").unwrap(), (3, 2));

        // Delete decrements; the emptied epoch bucket still counts toward
        // entitlement (epochs stays 2)
        store.delete_handles(&["y@a".to_string()]).unwrap();
        assert_eq!(store.storage_totals().unwrap(), (2, 62));
        assert_eq!(store.space_usage("@a").unwrap(), (2, 2));

        // space_usage_all only lists spaces with stored handles
        raw_insert(&store, "@b", "@b", 300, &[0u8; 5]);
        let mut all = store.space_usage_all().unwrap();
        all.sort();
        assert_eq!(
            all,
            vec![("@a".to_string(), 2, 2), ("@b".to_string(), 1, 1)]
        );
    }

    /// Reverse cleanup is precise: it extracts (num_id, rev) from the deleted
    /// zones, so reverse rows of *other* identities — even ones sharing a
    /// display name with the deleted handle — are never collateral damage.
    /// (Positive-path cleanup needs a real signed zone with a primary Sig and
    /// num_id, exercised via the handler paths; here we verify the guardrails:
    /// undecodable zones don't crash the delete and unrelated rows survive.)
    #[test]
    fn test_delete_handles_preserves_unrelated_reverse_rows() {
        let store = SqliteStore::in_memory().unwrap();
        raw_insert(&store, "x@a", "@a", 100, &[0u8; 10]);
        raw_insert(&store, "y@a", "@a", 100, &[0u8; 10]);

        // Reverse rows for other identities, one even sharing the deleted
        // handle's name — none may be touched by deleting x@a (its raw zone
        // blob carries no num_id).
        store
            .set_revs(&[("1", "x@a"), ("2", "x-pretty@a"), ("3", "y@a")])
            .unwrap();
        store
            .set_addrs("x@a", "x-pretty@a", &[("btc", "bc1qxyz")])
            .unwrap();

        let deleted = store.delete_handles(&["x@a".to_string()]).unwrap();
        assert_eq!(deleted, 1);

        let left = store.get_revs(&["1", "2", "3"]).unwrap();
        assert_eq!(left.len(), 3, "unrelated reverse rows must survive");
        assert!(
            store.get_addrs("btc", "bc1qxyz").unwrap().is_empty(),
            "addr index rows must be gone"
        );
    }

    /// Appended roots count against a hard combined page cap (roots can carry
    /// ~250 KB ZK receipts): when they don't fit, the main selection shrinks
    /// from the tail and the dropped rows arrive on the next page — the page
    /// never exceeds what pullers accept and never stops making progress.
    #[test]
    fn test_sync_page_trims_when_appended_roots_exceed_cap() {
        let store = SqliteStore::in_memory().unwrap();
        // Two spaces, each: one sub (30-byte zone) + one root (60-byte zone,
        // republished after the sub)
        raw_insert(&store, "x@a", "@a", 1, &[0u8; 30]);
        raw_insert(&store, "y@b", "@b", 1, &[0u8; 30]);
        raw_insert(&store, "@a", "@a", 1, &[0u8; 60]);
        raw_insert(&store, "@b", "@b", 1, &[0u8; 60]);
        for h in ["x@a", "y@b", "@a", "@b"] {
            store.bump_sync_seq(h).unwrap();
        }

        // Both subs fit max_bytes, but subs + both roots exceed the hard cap
        // (2x max_bytes) — the page must shrink to one sub + its root
        let max_bytes = 80;
        let page = store.sync_page(None, 2, max_bytes).unwrap();
        let total: usize = page
            .records
            .iter()
            .map(|r| r.cert.len() + r.zone.len())
            .sum();
        assert!(
            total <= 2 * max_bytes,
            "page ({total} bytes) must respect the hard cap"
        );
        let names: Vec<&str> = page.records.iter().map(|r| r.handle.as_str()).collect();
        assert!(names.contains(&"x@a") && names.contains(&"@a"));
        assert!(!names.contains(&"y@b"), "trimmed row waits for next page");
        assert_eq!(page.next_cursor.as_deref(), Some("1"), "cursor tracks trim");

        // The trimmed row arrives on the following page, with its root
        let cursor = page.next_cursor.unwrap().parse().ok();
        let page2 = store.sync_page(cursor, 2, max_bytes).unwrap();
        let names2: Vec<&str> = page2.records.iter().map(|r| r.handle.as_str()).collect();
        assert!(names2.contains(&"y@b") && names2.contains(&"@b"));
    }

    /// A root row popped by the trim while its sub-handles survive earlier in
    /// the page must be re-homed as an appended root — otherwise the page
    /// ships orphaned subs that a bootstrapping peer counts as failed and
    /// loses behind its watermark.
    #[test]
    fn test_sync_page_trim_rehomes_in_page_roots() {
        let store = SqliteStore::in_memory().unwrap();
        // Seq order: y@b (sub), z@c (sub), @b (root, in page range),
        // @c (root, beyond page — appended, and large enough to force a trim)
        raw_insert(&store, "y@b", "@b", 1, &[0u8; 30]);
        raw_insert(&store, "z@c", "@c", 1, &[0u8; 30]);
        raw_insert(&store, "@b", "@b", 1, &[0u8; 60]);
        raw_insert(&store, "@c", "@c", 1, &[0u8; 200]);
        for h in ["y@b", "z@c", "@b", "@c"] {
            store.bump_sync_seq(h).unwrap();
        }

        // All three in-range rows fit max_bytes; adding the appended @c root
        // busts the hard cap, so the trim pops @b (root — must be re-homed)
        // and then z@c (releasing @c). The page must keep y@b WITH @b.
        let page = store.sync_page(None, 3, 130).unwrap();
        let names: Vec<&str> = page.records.iter().map(|r| r.handle.as_str()).collect();
        assert!(names.contains(&"y@b"), "surviving sub stays");
        assert!(
            names.contains(&"@b"),
            "popped in-page root must be re-homed, not discarded"
        );
        assert!(!names.contains(&"z@c"), "trimmed sub waits for next page");
        assert_eq!(page.next_cursor.as_deref(), Some("1"));
        let total: usize = page
            .records
            .iter()
            .map(|r| r.cert.len() + r.zone.len())
            .sum();
        assert!(total <= 2 * 130, "cap still holds after re-homing");

        // Next page re-serves the trimmed rows with their root
        let page2 = store
            .sync_page(Some(resolver::SyncCursor(1)), 3, 130)
            .unwrap();
        let names2: Vec<&str> = page2.records.iter().map(|r| r.handle.as_str()).collect();
        assert!(names2.contains(&"z@c") && names2.contains(&"@c"));
    }

    /// The advertised cursor comes from the persistent counter, so evicting
    /// the newest rows can't look like a cursor-space reset to peers (which
    /// would trigger a needless full re-sync).
    #[test]
    fn test_latest_cursor_survives_eviction_of_newest_row() {
        let store = SqliteStore::in_memory().unwrap();
        raw_insert(&store, "a@s", "@s", 1, &[0u8; 4]);
        raw_insert(&store, "b@s", "@s", 1, &[0u8; 4]);
        store.bump_sync_seq("a@s").unwrap();
        store.bump_sync_seq("b@s").unwrap(); // b@s now holds the highest seq

        let before = store.sync_summary().unwrap().latest_cursor;
        assert_eq!(before.as_deref(), Some("2"));

        store.delete_handles(&["b@s".to_string()]).unwrap();
        assert_eq!(
            store.sync_summary().unwrap().latest_cursor,
            before,
            "eviction of the newest row must not regress the cursor"
        );
    }

    /// Eviction candidates come back oldest-updated first.
    #[test]
    fn test_eviction_candidates_order() {
        let store = SqliteStore::in_memory().unwrap();
        let conn = store.conn.lock().unwrap();
        for (handle, ts) in [("a@s", 300), ("b@s", 100), ("c@s", 200)] {
            conn.execute(
                "INSERT INTO handles (handle, space, cert_data, zone_data, epoch_height, updated_at)
                 VALUES (?, '@s', x'01', x'01', 1, ?)",
                params![handle, ts],
            )
            .unwrap();
        }
        drop(conn);
        assert_eq!(
            store.eviction_candidates("@s", 2).unwrap(),
            vec!["b@s".to_string(), "c@s".to_string()]
        );
    }

    #[test]
    fn test_open_in_memory() {
        let store = SqliteStore::in_memory().expect("create in-memory store");
        assert!(store.get_zones(&[]).unwrap().is_empty());
    }
}
