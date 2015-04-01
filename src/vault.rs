/*  Copyright 2015 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */

#![allow(unused_variables)]

extern crate routing;

#[path="data_manager/data_manager.rs"]
mod data_manager;
#[path="pmid_node/pmid_node.rs"]
mod pmid_node;
#[path="pmid_manager/pmid_manager.rs"]
mod pmid_manager;

use self::routing::Authority;
use self::routing::DestinationAddress;
use self::routing::DhtIdentity;
use self::routing::Action;
use self::routing::RoutingError;

use self::data_manager::DataManager;
use self::pmid_node::PmidNode;
use self::pmid_manager::PmidManager;

pub struct VaultFacade {
  data_manager : DataManager,
  pmid_manager : PmidManager,
  pmid_node : PmidNode
}

impl routing::Facade for VaultFacade {
  fn handle_get(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
    match our_authority {
      Authority::NaeManager => { return self.data_manager.handle_get(&data); }
      Authority::Node => { return self.pmid_node.handle_get(data); }
      _ => { return Err(RoutingError::InvalidRequest); }
    }
  }

  fn handle_put(&mut self, our_authority: Authority, from_authority: Authority,
                from_address: DhtIdentity, dest_address: DestinationAddress, data: Vec<u8>)->Result<Action, RoutingError> {
    match our_authority {
      Authority::NaeManager => { return self.data_manager.handle_put(&data); }
      Authority::Node => { return self.pmid_node.handle_put(&data); }
      Authority::NodeManager => { return self.pmid_manager.handle_put(&dest_address, &data); }
      _ => { return Err(RoutingError::InvalidRequest); }
    }
  }

  fn handle_post(&mut self, our_authority: Authority, from_authority: Authority, from_address: DhtIdentity, data: Vec<u8>)->Result<Action, RoutingError> {
    ;
    Err(RoutingError::InvalidRequest)
  }

  fn handle_get_response(&mut self, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_put_response(&mut self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

  fn handle_post_response(&mut self, from_authority: Authority, from_address: DhtIdentity, response: Result<Vec<u8>, RoutingError>) {
    ;
  }

}

impl VaultFacade {
  pub fn new() -> VaultFacade {
    VaultFacade { data_manager: DataManager::new(), pmid_manager: PmidManager::new(), pmid_node: PmidNode::new() }
  }
}