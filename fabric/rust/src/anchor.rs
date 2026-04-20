use crate::{AnchorSet, TrustId};
use libveritas::compute_trust_set;
use spaces_nums::RootAnchor;
use std::collections::HashMap;

const ANCHOR_SET_SIZE: usize = 60;

pub struct AnchorSets {
    pub sets: HashMap<TrustId, AnchorSet>,
}

impl AnchorSets {
    pub fn from_anchors(raw: Vec<RootAnchor>) -> Self {
        let mut sets = HashMap::new();
        for chunk in raw.chunks(ANCHOR_SET_SIZE) {
            let expanded = AnchorSet::from_anchors(chunk.to_vec());
            let trust_set = compute_trust_set(chunk);
            sets.insert(TrustId::from(trust_set.id), expanded);
        }
        Self { sets }
    }

    pub fn get(&self, key: TrustId) -> Option<&AnchorSet> {
        self.sets.get(&key)
    }

    pub fn latest(&self) -> Option<&AnchorSet> {
        self.sets
            .values()
            .max_by_key(|s| s.entries.last().map(|a| a.block.height).unwrap_or(0))
    }
}
