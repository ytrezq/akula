use super::helpers;
use crate::{
    h256_to_u256,
    kv::{
        mdbx::*,
        tables::{self, BitmapKey},
        MdbxWithDirHandle,
    },
    models::*,
};
use async_trait::async_trait;
use ethereum_jsonrpc::{types, ParityApiServer};
use jsonrpsee::core::RpcResult;
use std::{collections::BTreeSet, sync::Arc};

pub struct ParityApiServerImpl<SE>
where
    SE: EnvironmentKind,
{
    pub db: Arc<MdbxWithDirHandle<SE>>,
}

#[async_trait]
impl<DB> ParityApiServer for ParityApiServerImpl<DB>
where
    DB: EnvironmentKind,
{
    async fn list_storage_keys(
        &self,
        searched_address: Address,
        number_of_slots: usize,
        offset: Option<H256>,
        block_id: Option<types::BlockId>,
    ) -> RpcResult<Option<Vec<H256>>> {
        let tx = self.db.begin()?;

        Ok({
            match block_id {
                None
                | Some(types::BlockId::Number(types::BlockNumber::Latest))
                | Some(types::BlockId::Number(types::BlockNumber::Pending)) => {
                    // Simply traverse the current state

                    Some(
                        tx.cursor(tables::Storage)?
                            .walk_dup(searched_address, offset)
                            .take(number_of_slots)
                            .map(|res| res.map(|(slot, _)| slot))
                            .collect::<anyhow::Result<Vec<H256>>>()?,
                    )
                }
                Some(block_id) => {
                    // Traverse history index and add to set if non-zero at our block

                    if let Some((block_number, _)) = helpers::resolve_block_id(&tx, block_id)? {
                        let mut index = tx.cursor(tables::StorageHistory)?.walk(Some(BitmapKey {
                            inner: (searched_address, H256::zero()),
                            block_number: BlockNumber(0),
                        }));

                        let mut out = BTreeSet::new();

                        while let Some((
                            BitmapKey {
                                inner: (address, slot),
                                ..
                            },
                            _,
                        )) = index.next().transpose()?
                        {
                            if address != searched_address {
                                break;
                            }

                            if crate::accessors::state::storage::read(
                                &tx,
                                address,
                                h256_to_u256(slot),
                                Some(block_number),
                            )? != U256::ZERO
                            {
                                out.insert(slot);

                                if out.len() == number_of_slots {
                                    break;
                                }
                            }
                        }

                        Some(out.into_iter().collect())
                    } else {
                        None
                    }
                }
            }
        })
    }
}
