// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account_storage::AccountStorage, blob_register::BlobRegister, elder_stores::ElderStores,
    map_storage::MapStorage, sequence_storage::SequenceStorage,
};
use crate::cmd::NodeCmd;
use safe_nd::{AccountRead, BlobRead, DataQuery, MapRead, MsgEnvelope, SequenceRead};

pub(super) struct Reading {
    query: DataQuery,
    msg: MsgEnvelope,
}

impl Reading {
    pub fn new(query: DataQuery, msg: MsgEnvelope) -> Self {
        Self { query, msg }
    }

    pub fn get_result(&self, stores: &ElderStores) -> Option<NodeCmd> {
        use DataQuery::*;
        match &self.query {
            Blob(read) => self.blob(read, stores.blob_register()),
            Map(read) => self.map(read, stores.map_storage()),
            Sequence(read) => self.sequence(read, stores.sequence_storage()),
            Account(read) => self.account(read, stores.account_storage()),
        }
    }

    fn blob(&self, read: &BlobRead, register: &BlobRegister) -> Option<NodeCmd> {
        register.read(read, self.msg) // since the data is sent on to adults, the entire msg is passed in
    }

    fn map(&self, read: &MapRead, storage: &MapStorage) -> Option<NodeCmd> {
        storage.read(read, self.msg) // map data currently stay at elders, so the msg is not needed
    }

    fn sequence(&self, read: &SequenceRead, storage: &SequenceStorage) -> Option<NodeCmd> {
        storage.read(read, self.msg.id(), self.msg.origin) // sequence data currently stay at elders, so the msg is not needed
    }

    fn account(&self, read: &AccountRead, storage: &AccountStorage) -> Option<NodeCmd> {
        storage.read(read, self.msg.id(), self.msg.origin) // account data currently stay at elders, so the msg is not needed
    }
}