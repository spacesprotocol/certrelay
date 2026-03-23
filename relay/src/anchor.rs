use std::collections::HashMap;
use spaces_nums::RootAnchor;
use resolver::AnchorResponse;

const ANCHOR_SET_SIZE : usize = 60;

pub struct AnchorStore {
    pub anchors: HashMap<[u8;32], AnchorResponse>,
}

impl AnchorStore {
    pub fn from_anchors(raw: Vec<RootAnchor>) -> Self {
        let mut anchors = HashMap::new();
        for chunk in raw.chunks(ANCHOR_SET_SIZE) {
            let set = AnchorResponse::from_anchors(chunk.to_vec());
            anchors.insert(set.root, set);
        }
        Self { anchors }
    }

    pub fn get(&self, key: [u8;32]) -> Option<&AnchorResponse> {
        self.anchors.get(&key)
    }

    pub fn latest(&self) -> Option<&AnchorResponse> {
        self.anchors.values().max_by_key(|s| {
            s.entries.last().map(|a| a.block.height).unwrap_or(0)
        })
    }
}


