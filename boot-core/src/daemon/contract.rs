use std::fmt::Debug;

use serde::Serialize;

use crate::{BootError, Contract, Daemon, TxResponse};

impl Contract<Daemon> {
    /// Only upload the contract if it is not uploaded yet (checksum does not match)
    /// @TODO proper response
    pub fn upload_if_needed(&mut self) -> Result<Option<TxResponse<Daemon>>, BootError> {
        if self.latest_is_uploaded()? {
            log::info!("{} is already uploaded", self.id);
            Ok(None)
        } else {
            Some(self.upload()).transpose()
        }
    }

    /// Returns a bool whether the checksum of the wasm file matches the checksum of the previously uploaded code
    pub fn latest_is_uploaded(&self) -> Result<bool, BootError> {
        let latest_uploaded_code_id = self.code_id()?;
        let chain = self.get_chain();
        let on_chain_hash = chain
            .runtime
            .block_on(super::querier::DaemonQuerier::code_id_hash(
                chain.sender.channel(),
                latest_uploaded_code_id,
            ))?;
        let local_hash = self.source.checksum(&self.id)?;

        Ok(local_hash == on_chain_hash)
    }

    /// Only migrate the contract if it is not on the latest code-id yet
    pub fn migrate_if_needed(
        &mut self,
        migrate_msg: &(impl Serialize + Debug),
    ) -> Result<Option<TxResponse<Daemon>>, BootError> {
        if self.is_running_latest()? {
            log::info!("{} is already running the latest code", self.id);
            Ok(None)
        } else {
            Some(self.migrate(migrate_msg, self.code_id()?)).transpose()
        }
    }

    /// Returns a bool whether the contract is running the latest uploaded code for it
    pub fn is_running_latest(&self) -> Result<bool, BootError> {
        let latest_uploaded_code_id = self.code_id()?;
        let chain = self.get_chain();
        let info = chain
            .runtime
            .block_on(super::querier::DaemonQuerier::contract_info(
                chain.sender.channel(),
                self.address()?,
            ))?;

        Ok(latest_uploaded_code_id == info.code_id)
    }
}
