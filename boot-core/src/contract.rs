use std::path::Path;
use std::{
    cell::RefCell,
    fmt::{self, Debug},
    rc::Rc,
};
use std::{env, fs};

use crate::BootEnvironment;
use crate::{
    error::BootError, index_response::IndexResponse, state::StateInterface, tx_handler::TxResponse,
};
use cosmwasm_std::{Addr, Coin, CustomQuery, Empty};
use cw_multi_test::Contract as TestContract;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Serialize};

#[allow(unused)]
pub type StateReference<S> = Rc<RefCell<S>>;
/// An instance of a contract. Contains references to the execution environment (chain) and a local state (state)
/// The state is used to store contract addresses/code-ids
#[derive(Clone)]
pub struct Contract<Chain: BootEnvironment> {
    /// ID of the contract, used to retrieve addr/code-id
    pub id: String,
    pub(crate) source: ContractCodeReference,
    /// chain object that handles tx execution and queries.
    pub(crate) chain: Chain,
}

#[derive(Default)]
pub struct ContractCodeReference<ExecT = Empty, QueryT = Empty>
where
    ExecT: Clone + fmt::Debug + PartialEq + JsonSchema + DeserializeOwned + 'static,
    QueryT: CustomQuery + DeserializeOwned + 'static,
{
    pub wasm_code_path: Option<String>,
    pub contract_endpoints: Option<Box<dyn TestContract<ExecT, QueryT>>>,
}

impl Clone for ContractCodeReference {
    fn clone(&self) -> Self {
        Self {
            wasm_code_path: self.wasm_code_path.clone(),
            contract_endpoints: None,
        }
    }
}

impl<ExecT, QueryT> ContractCodeReference<ExecT, QueryT>
where
    ExecT: Clone + fmt::Debug + PartialEq + JsonSchema + DeserializeOwned + 'static,
    QueryT: CustomQuery + DeserializeOwned + 'static,
{
    /// Checks the environment for the wasm dir configuration and returns the path to the wasm file
    pub fn get_wasm_code_path(&self) -> Result<String, BootError> {
        let wasm_code_path = self
            .wasm_code_path
            .as_ref()
            .ok_or_else(|| BootError::StdErr("Wasm file is required to determine hash.".into()))?;

        let wasm_code_path = if wasm_code_path.contains(".wasm") {
            wasm_code_path.to_string()
        } else {
            format!(
                "{}/{}.wasm",
                env::var("ARTIFACTS_DIR").expect("ARTIFACTS_DIR is not set"),
                wasm_code_path
            )
        };

        Ok(wasm_code_path)
    }

    /// Calculate the checksum of the wasm file to compare against previous uploads
    pub fn checksum(&self, id: &str) -> Result<String, BootError> {
        let wasm_code_path = &self.get_wasm_code_path()?;
        if wasm_code_path.contains("artifacts") {
            // Now get local hash from optimization script
            let checksum_path = format!("{}/checksums.txt", wasm_code_path);
            let contents =
                fs::read_to_string(checksum_path).expect("Something went wrong reading the file");
            let parsed: Vec<&str> = contents.rsplit(".wasm").collect();
            let name = id.split(':').last().unwrap();
            let containing_line = parsed.iter().find(|line| line.contains(name)).unwrap();
            log::debug!("{:?}", containing_line);
            let local_hash = containing_line
                .trim_start_matches('\n')
                .split_whitespace()
                .next()
                .unwrap();
            return Ok(local_hash.into());
        }
        // Compute hash
        let wasm_code = Path::new(wasm_code_path);
        let checksum = sha256::try_digest(wasm_code)?;
        Ok(checksum)
    }
}

/// Expose chain and state function to call them on the contract
impl<Chain: BootEnvironment + Clone> Contract<Chain> {
    pub fn new(id: impl ToString, chain: Chain) -> Self {
        Contract {
            id: id.to_string(),
            chain,
            source: ContractCodeReference::default(),
        }
    }

    /// `get_chain` instead of `chain` to disambiguate from the std prelude .chain() method.
    pub fn get_chain(&self) -> &Chain {
        &self.chain
    }

    pub fn with_wasm_path(mut self, path: impl ToString) -> Self {
        self.source.wasm_code_path = Some(path.to_string());
        self
    }

    pub fn with_mock(mut self, mock_contract: Box<dyn TestContract<Empty, Empty>>) -> Self {
        self.source.contract_endpoints = Some(mock_contract);
        self
    }

    pub fn set_mock(&mut self, mock_contract: Box<dyn TestContract<Empty, Empty>>) {
        self.source.contract_endpoints = Some(mock_contract);
    }

    /// Sets the address of the contract in the local state
    pub fn with_address(self, address: Option<&Addr>) -> Self {
        if let Some(address) = address {
            self.set_address(address)
        }
        self
    }

    // Chain interfaces
    pub fn execute<E: Serialize + Debug>(
        &self,
        msg: &E,
        coins: Option<&[Coin]>,
    ) -> Result<TxResponse<Chain>, BootError> {
        log::info!("Executing {:#?} on {}", msg, self.id);
        let resp = self
            .chain
            .execute(msg, coins.unwrap_or(&[]), &self.address()?);
        log::debug!("execute response: {:?}", resp);
        resp
    }

    pub fn instantiate<I: Serialize + Debug>(
        &self,
        msg: &I,
        admin: Option<&Addr>,
        coins: Option<&[Coin]>,
    ) -> Result<TxResponse<Chain>, BootError> {
        log::info!("Instantiating {} with msg {:#?}", self.id, msg);
        let resp = self.chain.instantiate(
            self.code_id()?,
            msg,
            Some(&self.id),
            admin,
            coins.unwrap_or(&[]),
        )?;
        let contract_address = resp.instantiated_contract_address()?;
        self.set_address(&contract_address);
        log::info!("Instantiated {} with address {}", self.id, contract_address);
        log::debug!("Instantiate response: {:?}", resp);
        Ok(resp)
    }

    pub fn upload(&mut self) -> Result<TxResponse<Chain>, BootError> {
        log::info!("Uploading {}", self.id);
        let resp = self.chain.upload(&mut self.source)?;
        let code_id = resp.uploaded_code_id()?;
        self.set_code_id(code_id);
        log::info!("uploaded {} with code id {}", self.id, code_id);
        log::debug!("Upload response: {:?}", resp);
        Ok(resp)
    }

    pub fn query<Q: Serialize + Debug, T: Serialize + DeserializeOwned + Debug>(
        &self,
        query_msg: &Q,
    ) -> Result<T, BootError> {
        log::info!("Querying {:#?} on {}", query_msg, self.id);
        let resp = self.chain.query(query_msg, &self.address()?)?;
        log::debug!("Query response: {:?}", resp);
        Ok(resp)
    }

    pub fn migrate<M: Serialize + Debug>(
        &self,
        migrate_msg: &M,
        new_code_id: u64,
    ) -> Result<TxResponse<Chain>, BootError> {
        log::info!("Migrating {:?} to code_id {}", self.id, new_code_id);
        self.chain
            .migrate(migrate_msg, new_code_id, &self.address()?)
    }

    // State interfaces
    pub fn address(&self) -> Result<Addr, BootError> {
        self.chain.state().get_address(&self.id)
    }
    pub fn code_id(&self) -> Result<u64, BootError> {
        self.chain.state().get_code_id(&self.id)
    }
    pub fn set_address(&self, address: &Addr) {
        self.chain.state().set_address(&self.id, address)
    }
    pub fn set_code_id(&self, code_id: u64) {
        self.chain.state().set_code_id(&self.id, code_id)
    }
}
