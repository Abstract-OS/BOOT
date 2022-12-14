use std::collections::HashMap;

use cosmwasm_std::Addr;

use crate::BootError;

pub trait ChainState {
    type Out: StateInterface;
    fn state(&self) -> Self::Out;
}

/// Interface for setting the local (jsonified) state of the contracts on a chain
pub trait StateInterface: Clone {
    fn get_address(&self, contract_id: &str) -> Result<Addr, BootError>;
    fn set_address(&mut self, contract_id: &str, address: &Addr);
    fn get_code_id(&self, contract_id: &str) -> Result<u64, BootError>;
    fn set_code_id(&mut self, contract_id: &str, code_id: u64);
    fn get_all_addresses(&self) -> Result<HashMap<String, Addr>, BootError>;
    fn get_all_code_ids(&self) -> Result<HashMap<String, u64>, BootError>;
}
