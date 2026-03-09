use libveritas::cert::{PtrsSubtree, SpacesSubtree};
use libveritas::msg::ChainProof;
use spacedb::subtree::SubTree;
use spaces_client::jsonrpsee::http_client::HttpClient;
use spaces_client::rpc::RpcClient;
use spaces_ptr::{ChainProofRequest, RootAnchor};

pub struct SpacedClient {
    client: HttpClient,
    #[cfg(any(test, feature = "testutil"))]
    mock_chain_proof: Option<ChainProof>,
}

impl SpacedClient {
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            #[cfg(any(test, feature = "testutil"))]
            mock_chain_proof: None,
        }
    }

    #[cfg(any(test, feature = "testutil"))]
    pub fn mock(chain_proof: ChainProof) -> Self {
        use spaces_client::jsonrpsee::http_client::HttpClientBuilder;
        Self {
            client: HttpClientBuilder::default().build("http://nothanks.invalid").unwrap(),
            mock_chain_proof: Some(chain_proof),
        }
    }

    pub async fn get_root_anchors(&self) -> anyhow::Result<Vec<RootAnchor>> {
        Ok(self.client.get_root_anchors().await?)
    }

    pub async fn prove(&self, req: &ChainProofRequest) -> anyhow::Result<ChainProof> {
        #[cfg(any(test, feature = "testutil"))]
        if let Some(mock_chain_proof) = &self.mock_chain_proof {
            return Ok(mock_chain_proof.clone())
        }

        let res = self.client.build_chain_proof(req.clone(), None).await?;
        Ok(ChainProof {
            anchor: res.block,
            spaces: SpacesSubtree(SubTree::from_slice(&res.spaces_proof)?),
            ptrs: PtrsSubtree(SubTree::from_slice(&res.ptrs_proof)?),
        })
    }
}
