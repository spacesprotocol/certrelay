//! SQLite storage implementation for relay.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::anyhow;
use libveritas::cert::Certificate;
use libveritas::Zone;
use rusqlite::{params, Connection, OptionalExtension};
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
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handles_space ON handles(space);
"#;

/// Result of a bulk store operation.
#[derive(Debug, Default)]
pub struct BulkStoreResult {
    /// Number of handles stored (new or replaced existing).
    pub stored: usize,
    /// Number of handles skipped (existing zone was better).
    pub skipped: usize,
}

/// A handle record pairing a certificate with its zone.
pub struct HandleRecord {
    pub cert: Certificate,
    pub zone: Zone,
    /// Block height at which the space's commitment was made.
    pub epoch_height: u32,
    /// Offchain data sequence number.
    pub offchain_seq: u32,
    /// Delegate offchain data sequence number.
    pub delegate_offchain_seq: u32,
}

/// Lightweight row for hints queries (no blob deserialization).
pub struct HandleHintRow {
    pub handle: String,
    pub epoch_height: u32,
    pub offchain_seq: u32,
    pub delegate_offchain_seq: u32,
}

/// SQLite-backed store for handles.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (useful for testing).
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
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
            offchain_seq: u32,
            delegate_offchain_seq: u32,
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
            entries.push(Prepared {
                handle, space, cert_data, zone_data,
                epoch_height: update.epoch_height,
                offchain_seq: update.offchain_seq,
                delegate_offchain_seq: update.delegate_offchain_seq,
            });
        }

        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        // Bulk SELECT: get existing zones for comparison
        let handles: Vec<&str> = entries.iter().map(|e| e.handle.as_str()).collect();
        let existing_zones = Self::get_zones_inner(&conn, &handles)?;

        // Filter to entries where the incoming zone is better (or new)
        let to_store: Vec<_> = entries
            .into_iter()
            .zip(updates.iter())
            .filter(|(e, update)| {
                match existing_zones.get(e.handle.as_str()) {
                    Some(existing) => update.zone.is_better_than(existing).unwrap_or(false),
                    None => true,
                }
            })
            .map(|(e, _)| e)
            .collect();

        let skipped = updates.len() - to_store.len();

        if to_store.is_empty() {
            return Ok(BulkStoreResult { stored: 0, skipped });
        }

        // Bulk INSERT
        let placeholders: Vec<String> =
            to_store.iter().map(|_| "(?, ?, ?, ?, ?, ?, ?, ?)".to_string()).collect();
        let query = format!(
            "INSERT OR REPLACE INTO handles (handle, space, cert_data, zone_data, epoch_height, offchain_seq, delegate_offchain_seq, updated_at) VALUES {}",
            placeholders.join(", ")
        );

        let mut params: Vec<Box<dyn rusqlite::ToSql>> =
            Vec::with_capacity(to_store.len() * 8);
        for e in &to_store {
            params.push(Box::new(e.handle.clone()));
            params.push(Box::new(e.space.clone()));
            params.push(Box::new(e.cert_data.clone()));
            params.push(Box::new(e.zone_data.clone()));
            params.push(Box::new(e.epoch_height));
            params.push(Box::new(e.offchain_seq));
            params.push(Box::new(e.delegate_offchain_seq));
            params.push(Box::new(now));
        }

        let param_refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        conn.execute(&query, param_refs.as_slice())?;

        Ok(BulkStoreResult { stored: to_store.len(), skipped })
    }

    /// Get a single handle record.
    pub fn get_handle(&self, handle: &str) -> anyhow::Result<Option<HandleRecord>> {
        let conn = self.conn.lock().unwrap();

        let row: Option<(Vec<u8>, Vec<u8>, u32, u32, u32)> = conn
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
                Ok(Some(HandleRecord { cert, zone, epoch_height, offchain_seq, delegate_offchain_seq }))
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
        let params: Vec<&dyn rusqlite::ToSql> = handles
            .iter()
            .map(|h| h as &dyn rusqlite::ToSql)
            .collect();

        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, u32>(2)?, row.get::<_, u32>(3)?, row.get::<_, u32>(4)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            let (cert_bytes, zone_bytes, epoch_height, offchain_seq, delegate_offchain_seq) = row?;
            let cert: Certificate = borsh::from_slice(&cert_bytes)
                .map_err(|e| anyhow!("failed to deserialize certificate: {}", e))?;
            let zone: Zone = borsh::from_slice(&zone_bytes)
                .map_err(|e| anyhow!("failed to deserialize zone: {}", e))?;
            results.push(HandleRecord { cert, zone, epoch_height, offchain_seq, delegate_offchain_seq });
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
            "SELECT handle, epoch_height, offchain_seq, delegate_offchain_seq FROM handles WHERE handle IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::ToSql> = handles
            .iter()
            .map(|h| h as &dyn rusqlite::ToSql)
            .collect();

        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(HandleHintRow {
                handle: row.get(0)?,
                epoch_height: row.get(1)?,
                offchain_seq: row.get(2)?,
                delegate_offchain_seq: row.get(3)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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
        let params: Vec<&dyn rusqlite::ToSql> = handles
            .iter()
            .map(|h| h as &dyn rusqlite::ToSql)
            .collect();

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let store = SqliteStore::in_memory().expect("create in-memory store");
        assert!(store.get_zones(&[]).unwrap().is_empty());
    }
}
