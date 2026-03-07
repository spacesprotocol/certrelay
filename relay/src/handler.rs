use libveritas::cert::{ChainProofRequestUtils, HandleSubtree, Witness};
use libveritas::msg::{self, Handle, QueryContext};
use libveritas::sname::{Label, NameLike, SName};
use libveritas::{ProvableOption, Veritas, Zone};
use spacedb::Hash;
use spacedb::subtree::SubTree;
use spaces_protocol::slabel::SLabel;
use spaces_ptr::ChainProofRequest;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Mutex;
use resolver::{EpochResult, HandleHint, SpaceHint};
use crate::anchor::AnchorStore;
use crate::spaced::SpacedClient;
use crate::store::{HandleRecord, SqliteStore};

/// Certificate handler that verifies messages and stores zones/handles.
pub struct Handler {
    pub veritas: Mutex<Veritas>,
    pub anchor_store: Mutex<AnchorStore>,
    pub store: SqliteStore,
}

impl Handler {
    pub fn new(veritas: Veritas, store: SqliteStore, anchor_store: AnchorStore) -> Self {
        Self {
            veritas: Mutex::new(veritas),
            anchor_store: Mutex::new(anchor_store),
            store,
        }
    }

    /// Resolve queries into a certificate message.
    ///
    /// Takes a list of wire-format queries (plain strings) and builds a Message
    /// containing the certificates and chain proofs needed to verify them.
    pub async fn resolve(
        &self,
        chain: &SpacedClient,
        queries: Vec<resolver::Query>,
    ) -> anyhow::Result<msg::Message> {
        let mut bundles: Vec<msg::Bundle> = Vec::with_capacity(queries.len());
        let mut seen_spaces: HashSet<String> = HashSet::new();

        for query in queries {
            if !seen_spaces.insert(query.space.clone()) {
                continue; // Skip duplicate spaces
            }

            let space = SLabel::from_str(&query.space)
                .map_err(|_| anyhow::anyhow!("invalid space: {}", query.space))?;

            // Load root handle (has zone + parent cert)
            let parent = match self.store.get_handle(&query.space)? {
                Some(record) => record,
                None => continue,
            };
            let mut receipt = match parent.cert.witness {
                Witness::Root { receipt } => receipt,
                _ => continue,
            };

            // Skip receipt if client can verify from their cached epoch
            if query
                .epoch_hint
                .as_ref()
                .is_some_and(|h| epoch_hint_verifiable_by(h, &parent.zone))
            {
                receipt = None;
            }
            let unique_handles: Vec<String> = query
                .handles
                .iter()
                .filter_map(|h| Label::from_str(h).ok())
                .collect::<HashSet<_>>()
                .into_iter()
                .filter_map(|h| SName::join(&h, &space).ok())
                .map(|sname| sname.to_string())
                .collect();

            let handle_refs: Vec<&str> = unique_handles.iter().map(|s| s.as_str()).collect();
            let handle_entries = self.store.get_handles(&handle_refs)?;

            let mut certs_by_epoch: HashMap<Hash, msg::Epoch> = HashMap::new();
            for record in handle_entries {
                let (handle, handle_tree) = match record.cert.witness {
                    Witness::Leaf {
                        genesis_spk,
                        handles,
                        signature,
                    } => {
                        let name = match record.cert.subject.subspace() {
                            Some(n) => n,
                            None => continue,
                        };
                        (
                            Handle {
                                name,
                                genesis_spk,
                                data: record.zone.offchain_data,
                                signature,
                            },
                            handles,
                        )
                    }
                    _ => continue,
                };

                let epoch_root = match handle_tree.compute_root() {
                    Ok(root) => root,
                    Err(_) => continue,
                };

                let epoch = certs_by_epoch
                    .entry(epoch_root)
                    .or_insert_with(|| msg::Epoch {
                        tree: HandleSubtree(SubTree::empty()),
                        handles: vec![],
                    });

                let merged_tree = std::mem::replace(&mut epoch.tree.0, SubTree::empty());
                epoch.tree.0 = match merged_tree.merge(handle_tree.0) {
                    Ok(tree) => tree,
                    Err(_) => continue,
                };
                epoch.handles.push(handle);
            }

            let delegate_offchain_data = match &parent.zone.delegate {
                ProvableOption::Exists { value: d } => d.offchain_data.clone(),
                _ => None,
            };

            bundles.push(msg::Bundle {
                space,
                receipt,
                epochs: certs_by_epoch.into_values().collect(),
                offchain_data: parent.zone.offchain_data.clone(),
                delegate_offchain_data,
            });
        }

        // Build chain proof request
        let mut chain_req = ChainProofRequest {
            spaces: vec![],
            ptrs_keys: vec![],
        };

        for bundle in &bundles {
            for epoch in &bundle.epochs {
                chain_req.add_subtree(&bundle.space, &epoch.tree);
            }
        }

        let chain = chain.prove(&chain_req).await?;

        Ok(msg::Message {
            chain,
            spaces: bundles,
        })
    }

    pub fn hints(&self, handles: &mut [&str]) -> anyhow::Result<resolver::HintsResponse> {
        handles.sort();
        if let Some(w) = handles.windows(2).find(|w| w[0] == w[1]) {
            return Err(anyhow::anyhow!("duplicate handle: {}", w[0]));
        }

        let mut res = resolver::HintsResponse {
            anchor_tip: self.veritas.lock().expect("lock").newest_anchor(),
            hints: vec![],
        };

        let all_rows = self.store.get_handle_hints(handles)?;
        for space in handles.iter().filter(|h| h.starts_with("@") || h.starts_with("#")) {
            let Some(space_row) = all_rows
                .iter()
                .find(|r| &r.handle == space) else {
                continue;
            };

            let mut hint = SpaceHint {
                epoch_tip: space_row.epoch_height,
                name: space.to_string(),
                seq: space_row.offchain_seq,
                delegate_seq: space_row.delegate_offchain_seq,
                epochs: vec![],
            };
            for row in all_rows
                .iter().filter(|r| r.handle.ends_with(space) && r.handle != *space)
                .collect::<Vec<_>>() {
                let idx = hint.epochs.iter()
                    .position(|x| x.epoch == row.epoch_height)
                    .unwrap_or_else(|| {
                        hint.epochs.push(EpochResult {
                            epoch: row.epoch_height,
                            res: vec![],
                        });
                        hint.epochs.len() - 1
                    });

                let item = &mut hint.epochs[idx];
                item.res.push(HandleHint {
                    seq: row.offchain_seq,
                    name: row.handle.clone(),
                })
            }
            res.hints.push(hint);
        }
        Ok(res)
    }

    /// Handle an incoming certificate message.
    ///
    /// Verifies the message against the current chain state, updates stored zones,
    /// and stores any new handle records.
    pub fn handle_message(&self, msg: msg::Message) -> anyhow::Result<()> {
        // Build query context from stored zones
        let mut ctx = QueryContext::new();
        let spaces: Vec<&SLabel> = msg.spaces.iter().map(|s| &s.space).collect();
        let zones = self.store.get_zones(&spaces)?;
        for zone in zones {
            ctx.add_zone(zone);
        }

        // Verify the message
        let res = self.veritas.lock().unwrap().verify_message(&ctx, msg)?;

        // Build zone lookup by handle and epoch height by space
        let mut zone_map: HashMap<String, &Zone> = HashMap::new();
        let mut epoch_map: HashMap<String, u32> = HashMap::new();
        for zone in &res.zones {
            zone_map.insert(zone.handle.to_string(), zone);
            // Root zones (single-label like "@bitcoin") carry the commitment
            if zone.handle.is_single_label() {
                let epoch_height = match &zone.commitment {
                    ProvableOption::Exists { value: c } => c.onchain.block_height,
                    _ => 0,
                };
                epoch_map.insert(zone.handle.to_string(), epoch_height);
            }
        }

        // Bundle each certificate with its zone and epoch height
        let updates: Vec<HandleRecord> = res
            .certificates()
            .filter_map(|cert| {
                let zone = zone_map.get(&cert.subject.to_string())?;
                let space = cert.subject.space()?.to_string();
                let epoch_height = epoch_map.get(&space).copied().unwrap_or(0);
                let offchain_seq = zone.offchain_data.as_ref().map(|d| d.seq).unwrap_or(0);
                let delegate_offchain_seq = match &zone.delegate {
                    ProvableOption::Exists { value: d } => {
                        d.offchain_data.as_ref().map(|d| d.seq).unwrap_or(0)
                    }
                    _ => 0,
                };
                Some(HandleRecord {
                    cert,
                    zone: (*zone).clone(),
                    epoch_height,
                    offchain_seq,
                    delegate_offchain_seq,
                })
            })
            .collect();

        let result = self.store.update_handles(&updates)?;
        tracing::debug!(
            "stored {} handles, skipped {} (existing zone was better)",
            result.stored,
            result.skipped
        );

        Ok(())
    }
}

/// Check if a wire-format epoch hint is verifiable by a zone.
/// Only checks height - the root is used by clients, not the relay.
fn epoch_hint_verifiable_by(hint: &resolver::EpochHint, zone: &Zone) -> bool {
    if let ProvableOption::Exists { value: c } = &zone.commitment {
        c.onchain.block_height >= hint.height
    } else {
        false
    }
}
