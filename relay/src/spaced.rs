use libveritas::cert::{NumsSubtree, SpacesSubtree};
use libveritas::msg::ChainProof;
use spacedb::subtree::SubTree;
use spaces_client::jsonrpsee::http_client::HttpClient;
use spaces_client::rpc::RpcClient;
use spaces_nums::{ChainProofRequest, RootAnchor};
#[cfg(any(test, feature = "testutil"))]
use std::ops::Deref;
#[cfg(any(test, feature = "testutil"))]
use std::sync::Mutex;

pub struct SpacedClient {
    client: HttpClient,
    #[cfg(any(test, feature = "testutil"))]
    pub mock_chain_proof: Mutex<Option<(ChainProof, Vec<RootAnchor>)>>,
}

impl SpacedClient {
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            #[cfg(any(test, feature = "testutil"))]
            mock_chain_proof: Mutex::new(None),
        }
    }

    #[cfg(any(test, feature = "testutil"))]
    pub fn mock((proof, anchors): (ChainProof, Vec<RootAnchor>)) -> Self {
        use spaces_client::jsonrpsee::http_client::HttpClientBuilder;
        Self {
            client: HttpClientBuilder::default()
                .build("http://nothanks.invalid")
                .unwrap(),
            mock_chain_proof: Mutex::new(Some((proof, anchors))),
        }
    }

    pub async fn get_root_anchors(&self) -> anyhow::Result<Vec<RootAnchor>> {
        #[cfg(any(test, feature = "testutil"))]
        if let Some((_, anchors)) = &self.mock_chain_proof.lock().unwrap().deref() {
            return Ok(anchors.clone());
        }
        Ok(self.client.get_root_anchors().await?)
    }

    pub async fn prove(&self, req: &ChainProofRequest) -> anyhow::Result<ChainProof> {
        #[cfg(any(test, feature = "testutil"))]
        if let Some((p, _)) = &self.mock_chain_proof.lock().unwrap().deref() {
            return Ok(p.clone());
        }

        let res = self.client.build_chain_proof(req.clone(), None).await?;
        Ok(ChainProof {
            anchor: res.block,
            spaces: SpacesSubtree(SubTree::from_slice(&res.spaces_proof)?),
            nums: NumsSubtree(SubTree::from_slice(&res.ptrs_proof)?),
        })
    }
}
