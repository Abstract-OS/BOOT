use cosmwasm_std::{Addr, Empty, Event};
use cw_multi_test::{next_block, App, AppResponse, BasicApp, Executor};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    contract::ContractCodeReference,
    state::{ChainState, StateInterface},
    tx_handler::TxHandler,
    BootError, Contract,
};
use std::{cell::RefCell, fmt::Debug, rc::Rc};

use super::state::MockState;

pub fn instantiate_default_mock_env(
    sender: &Addr,
) -> anyhow::Result<(Rc<RefCell<MockState>>, Mock<MockState>)> {
    let mock_state = Rc::new(RefCell::new(MockState::new()));
    let mock_app = Rc::new(RefCell::new(BasicApp::new(|_, _, _| {})));
    let mock_chain = Mock::new(sender, &mock_state, &mock_app)?;
    Ok((mock_state, mock_chain))
}
pub fn instantiate_custom_mock_env<S: StateInterface>(
    sender: &Addr,
    custom_state: S,
) -> anyhow::Result<(Rc<RefCell<S>>, Mock<S>)> {
    let mock_state = Rc::new(RefCell::new(custom_state));
    let mock_app = Rc::new(RefCell::new(BasicApp::new(|_, _, _| {})));
    let mock_chain = Mock::new(sender, &mock_state, &mock_app)?;
    Ok((mock_state, mock_chain))
}

// Generic mock-chain implementation
// Allows for custom state storage
#[derive(Clone)]
pub struct Mock<S: StateInterface = MockState> {
    pub sender: Addr,
    pub state: Rc<RefCell<S>>,
    pub app: Rc<RefCell<App>>,
}

impl<S: StateInterface> Mock<S> {
    /// set the Bank balance of an address
    pub fn init_balance(
        &self,
        address: &Addr,
        amount: Vec<cosmwasm_std::Coin>,
    ) -> Result<(), BootError> {
        self.app
            .borrow_mut()
            .init_modules(|router, _, storage| router.bank.init_balance(storage, address, amount))
            .map_err(Into::into)
    }
}

impl<S: StateInterface> Mock<S> {
    pub fn new(
        sender: &Addr,
        state: &Rc<RefCell<S>>,
        app: &Rc<RefCell<App>>,
    ) -> anyhow::Result<Self> {
        let instance = Self {
            sender: sender.clone(),
            state: state.clone(),
            app: app.clone(),
        };
        Ok(instance)
    }
}

impl<S: StateInterface> ChainState for Mock<S> {
    type Out = Rc<RefCell<S>>;

    fn state(&self) -> Self::Out {
        Rc::clone(&self.state)
    }
}

impl<S: StateInterface> StateInterface for Rc<RefCell<S>> {
    fn get_address(&self, contract_id: &str) -> Result<Addr, BootError> {
        self.borrow().get_address(contract_id)
    }

    fn set_address(&mut self, contract_id: &str, address: &Addr) {
        self.borrow_mut().set_address(contract_id, address)
    }

    fn get_code_id(&self, contract_id: &str) -> Result<u64, BootError> {
        self.borrow().get_code_id(contract_id)
    }

    fn set_code_id(&mut self, contract_id: &str, code_id: u64) {
        self.borrow_mut().set_code_id(contract_id, code_id)
    }

    fn get_all_addresses(&self) -> Result<std::collections::HashMap<String, Addr>, BootError> {
        self.borrow().get_all_addresses()
    }
    fn get_all_code_ids(&self) -> Result<std::collections::HashMap<String, u64>, BootError> {
        self.borrow().get_all_code_ids()
    }
}

// Execute on the test chain, returns test response type
impl<S: StateInterface> TxHandler for Mock<S> {
    type Response = AppResponse;
    fn sender(&self) -> Addr {
        self.sender.clone()
    }
    fn execute<E: Serialize + Debug>(
        &self,
        exec_msg: &E,
        coins: &[cosmwasm_std::Coin],
        contract_address: &Addr,
    ) -> Result<Self::Response, crate::BootError> {
        self.app
            .borrow_mut()
            .execute_contract(
                self.sender.clone(),
                contract_address.to_owned(),
                exec_msg,
                coins,
            )
            .map_err(From::from)
    }

    fn instantiate<I: Serialize + Debug>(
        &self,
        code_id: u64,
        init_msg: &I,
        label: Option<&str>,
        admin: Option<&Addr>,
        coins: &[cosmwasm_std::Coin],
    ) -> Result<Self::Response, crate::BootError> {
        let addr = self.app.borrow_mut().instantiate_contract(
            code_id,
            self.sender.clone(),
            init_msg,
            coins,
            label.unwrap_or("contract_init"),
            admin.map(|a| a.to_string()),
        )?;
        // add contract address to events manually
        let mut event = Event::new("instantiate");
        event = event.add_attribute("_contract_address", addr);
        let resp = AppResponse {
            events: vec![event],
            ..Default::default()
        };
        Ok(resp)
    }

    fn query<Q: Serialize + Debug, T: Serialize + DeserializeOwned>(
        &self,
        query_msg: &Q,
        contract_address: &Addr,
    ) -> Result<T, crate::BootError> {
        self.app
            .borrow()
            .wrap()
            .query_wasm_smart(contract_address, query_msg)
            .map_err(From::from)
    }

    fn migrate<M: Serialize + Debug>(
        &self,
        migrate_msg: &M,
        new_code_id: u64,
        contract_address: &Addr,
    ) -> Result<Self::Response, crate::BootError> {
        self.app
            .borrow_mut()
            .migrate_contract(
                self.sender.clone(),
                contract_address.clone(),
                migrate_msg,
                new_code_id,
            )
            .map_err(From::from)
    }

    fn upload(
        &self,
        contract_source: &mut ContractCodeReference<Empty>,
    ) -> Result<Self::Response, crate::BootError> {
        // transfer ownership of Boxed app to App
        if let Some(contract) = std::mem::replace(&mut contract_source.contract_endpoints, None) {
            let code_id = self.app.borrow_mut().store_code(contract);
            // add contract code_id to events manually
            let mut event = Event::new("store_code");
            event = event.add_attribute("code_id", code_id.to_string());
            let resp = AppResponse {
                events: vec![event],
                ..Default::default()
            };
            Ok(resp)
        } else {
            Err(BootError::StdErr(
                "Contract reference must be cosm-multi-test contract object.".into(),
            ))
        }
    }

    fn wait_blocks(&self, amount: u64) -> Result<(), BootError> {
        self.app.borrow_mut().update_block(|b| {
            b.height += amount;
            b.time = b.time.plus_seconds(5 * amount);
        });
        Ok(())
    }
    fn next_block(&self) -> Result<(), BootError> {
        self.app.borrow_mut().update_block(next_block);
        Ok(())
    }
    fn block_info(&self) -> Result<cosmwasm_std::BlockInfo, BootError> {
        Ok(self.app.borrow().block_info())
    }
}

impl Contract<Mock> {
    pub fn set_sender(&mut self, sender: Addr) -> &mut Self {
        self.chain.sender = sender;
        self
    }
}
