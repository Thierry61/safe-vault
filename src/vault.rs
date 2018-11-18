// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use authority::{ClientAuthority, ClientManagerAuthority};
use cache::Cache;
#[cfg(feature = "use-mock-crust")]
use chunk_store::Error as ChunkStoreError;
use config_handler::{self, Config};
use error::InternalError;
use maidsafe_utilities::serialisation;
#[cfg(all(test, feature = "use-mock-routing"))]
pub use mock_routing::Node as RoutingNode;
#[cfg(all(test, feature = "use-mock-routing"))]
use mock_routing::NodeBuilder;
use personas::data_manager::{DataId, MutableDataId};
use personas::data_manager::{self, DataManager};
use personas::maid_manager::{self, MaidManager};
#[cfg(feature = "use-mock-crypto")]
use routing::mock_crypto::rust_sodium;
#[cfg(feature = "use-mock-crust")]
use routing::Config as RoutingConfig;
pub use routing::Event;
#[cfg(not(all(test, feature = "use-mock-routing")))]
pub use routing::Node as RoutingNode;
#[cfg(not(all(test, feature = "use-mock-routing")))]
use routing::NodeBuilder;
use routing::{Authority, EventStream, Request, Response, RoutingTable, XorName, Prefix};
#[cfg(not(feature = "use-mock-crypto"))]
use rust_sodium;
use rust_sodium::crypto::sign;
use serde_json;
use serde::{Serialize, Serializer};
use hex;
use std::collections::{BinaryHeap, BTreeMap, BTreeSet};
use hostname::get_hostname;

// Structure to serialize section definiton in JSON format
#[derive(Default, Serialize)]
struct Section {
    // Base 2 string representation
    #[serde(serialize_with = "serialize_prefix")]
    prefix: Prefix<XorName>,
    // Version number
    version: u64,
    // Array of hex string representation
    #[serde(serialize_with = "serialize_xor_names")]
    ids: BTreeSet<XorName>,
}

// Structure to serialize vault data in JSON format
#[derive(Default, Serialize)]
struct VaultData {
    #[serde(serialize_with = "serialize_xor_name")]
    name: XorName,
    immutable_data: u64,
    mutable_data: u64,
    type_tags: BTreeMap<String, u64>,
    used_space: u64,
    max_space: u64,
    #[serde(serialize_with = "serialize_xor_names")]
    immutable_data_set: BTreeSet<XorName>,
    #[serde(serialize_with = "serialize_xor_names_and_tags")]
    mutable_data_set: BTreeSet<(XorName, u64)>,
    sections: Vec<Section>,
    hostname: String,
}

impl VaultData {
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

// Prefix<XorName> to base 2 string
pub fn serialize_prefix<S: Serializer>(prefix: &Prefix<XorName>, serializer: S) -> Result<S::Ok, S::Error> {
    let prefix = format!("{:b}", prefix);
    serializer.serialize_str(&prefix)
}

// Length of serialized ids
const ID_LENGTH: usize = 4;

// XorName to hex string
pub fn serialize_xor_name<S: Serializer>(id: &XorName, serializer: S) -> Result<S::Ok, S::Error> {
    let id = format!("{}", hex::encode(id[0..ID_LENGTH].as_ref()));
    id.serialize(serializer)
}

// Vector of XorName to vector of hex string
pub fn serialize_xor_names<S: Serializer>(ids: &BTreeSet<XorName>, serializer: S) -> Result<S::Ok, S::Error> {
    let ids = ids.iter()
                 .map(|id| format!("{}", hex::encode(id[0..ID_LENGTH].as_ref())))
                 .collect::<BinaryHeap<String>>()
                 .into_sorted_vec();
    ids.serialize(serializer)
}

// Vector of (XorName, u64) tuples to vector of 2 elements arrays (hex string + number)
pub fn serialize_xor_names_and_tags<S: Serializer>(ids_and_tags: &BTreeSet<(XorName, u64)>, serializer: S) -> Result<S::Ok, S::Error> {
    let ids_and_tags = ids_and_tags.iter()
                 .map(|(id, tag)| (format!("{}", hex::encode(id[0..ID_LENGTH].as_ref())), *tag))
                 .collect::<BinaryHeap<(String, u64)>>()
                 .into_sorted_vec();
    ids_and_tags.serialize(serializer)
}

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    maid_manager: MaidManager,
    data_manager: DataManager,
    routing_node: RoutingNode,
    type_tags: BTreeMap<u64, String>,
    data_ids: bool,
}

impl Vault {
    /// Creates a network Vault instance.
    pub fn new(first_vault: bool, use_cache: bool) -> Result<Self, InternalError> {
        let config = config_handler::read_config_file().map_err(|error| {
            warn!("Failed to parse vault config file: {:?}", error);
            error
        })?;
        let builder = RoutingNode::builder().first(first_vault);
        Self::vault_with_config(builder, use_cache, config)
    }

    fn vault_with_config(
        builder: NodeBuilder,
        use_cache: bool,
        config: Config,
    ) -> Result<Self, InternalError> {
        let _ = rust_sodium::init();
        let disable_mutation_limit = config
            .dev
            .as_ref()
            .map_or(false, |dev_config| dev_config.disable_mutation_limit);
        let routing_node = if use_cache {
            builder.cache(Box::new(Cache::new())).create()
        } else {
            builder.create()
        }?;
        let group_size = routing_node.min_section_size();

        // Index tags by id
        let mut type_tags = BTreeMap::new();
        let mut data_ids = false;
        if let Some(stats) = config.stats {
            for (tag_label, tag_ids) in &stats.type_tags {
                for tag_id in tag_ids.iter() {
                    let _ = type_tags.insert(*tag_id, tag_label.to_string());
                }
            }
            data_ids = stats.data_ids;
        }

        Ok(Vault {
            maid_manager: MaidManager::new(
                group_size,
                config.invite_key.map(sign::PublicKey),
                disable_mutation_limit,
            ),
            data_manager: DataManager::new(
                group_size,
                config.chunk_store_root,
                config.max_capacity,
            )?,
            routing_node,
            type_tags,
            data_ids,
        })
    }

    /// Run the event loop, processing events received from Routing.
    pub fn run(&mut self) -> Result<bool, InternalError> {
        while let Ok(event) = self.routing_node.next_ev() {
            match self.process_event(event) {
                EventResult::Terminate => return Ok(true),
                EventResult::Restart => return Ok(false),
                _ => (),
            }
        }

        // FIXME: decide if we want to restart here (in which case return `Ok(false)`).
        Ok(true)
    }

    fn process_event(&mut self, event: Event) -> EventResult {
        #[cfg(feature = "use-mock-crust")]
        self.data_manager.pop_group_refresh(&mut self.routing_node);

        let mut res = EventResult::Processed;
        let event_res = match event {
            Event::Request { request, src, dst } => self.on_request(request, src, dst),
            Event::Response { response, src, dst } => self.on_response(response, src, dst),
            Event::NodeAdded(node_added, routing_table) => {
                self.on_node_added(node_added, routing_table)
            }
            Event::NodeLost(node_lost, routing_table) => {
                self.on_node_lost(node_lost, routing_table)
            }
            Event::RestartRequired => {
                warn!("Restarting Vault");
                res = EventResult::Restart;
                Ok(())
            }
            Event::Terminate => {
                res = EventResult::Terminate;
                Ok(())
            }
            Event::SectionSplit(_) | Event::SectionMerge(_) | Event::Connected => {
                res = EventResult::Ignored;
                Ok(())
            }
            Event::Tick => {
                self.log_vault_data();
                res = EventResult::Ignored;
                Ok(())
            }
        };

        if let Err(error) = event_res {
            debug!("Failed to handle event: {:?}", error);
        }

        self.data_manager.check_timeouts(&mut self.routing_node);
        res
    }

    // Log vault data about every mn (in a specific target, to allow a specific appender)
    fn log_vault_data(&mut self) {
        // Get summary from data manager
        let mut vd : VaultData = Default::default();
        for data_id in self.data_manager.our_chunks() {
            match data_id {
                DataId::Mutable(MutableDataId(name, tag)) => {
                    vd.mutable_data += 1;
                    if let Some(tag_label) = self.type_tags.get(&tag) {
                        *vd.type_tags.entry(tag_label.to_string()).or_insert(0) += 1;
                    }
                    if self.data_ids {
                        let _ = vd.mutable_data_set.insert((name, tag));
                    }
                },
                DataId::Immutable(name) => {
                    vd.immutable_data += 1;
                    if self.data_ids {
                        let _ = vd.immutable_data_set.insert(name.0);
                    }
                }
            }
        }
        // Get chunk store data
        let chunk_store = self.data_manager.chunk_store();
        vd.used_space = chunk_store.used_space();
        vd.max_space = chunk_store.max_space();
        // Get relocated name from routing table
        let rt = self.routing_node.routing_table().unwrap();
        vd.name = *rt.our_name();
        // Get neighbouring sections
        vd.sections = rt.all_sections()
            .into_iter()
            .map(|(p, (v, section))| Section { prefix: p, version: v, ids: section })
            .collect::<Vec<Section>>();
        // Get hostname
        vd.hostname = get_hostname().unwrap();
        // Log vault data
        info!(target: "vault_stats", "{}", vd.to_json_string());
    }

    fn on_request(
        &mut self,
        request: Request,
        src: Authority<XorName>,
        dst: Authority<XorName>,
    ) -> Result<(), InternalError> {
        match (src, dst, request) {
            // ================== Refresh ==================
            (
                Authority::ClientManager(_),
                Authority::ClientManager(_),
                Request::Refresh(serialised_msg, msg_id),
            )
            | (
                Authority::ClientManager(_),
                Authority::ManagedNode(_),
                Request::Refresh(serialised_msg, msg_id),
            ) => self.maid_manager.handle_serialised_refresh(
                &mut self.routing_node,
                &serialised_msg,
                msg_id,
                None,
            ),
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Request::Refresh(serialised_msg, msg_id),
            ) => match serialisation::deserialise::<Refresh>(&serialised_msg)? {
                Refresh::MaidManager(refresh) => self.maid_manager.handle_refresh(
                    &mut self.routing_node,
                    refresh,
                    msg_id,
                    Some(src_name),
                ),
                Refresh::DataManager(refreshes) => {
                    self.data_manager
                        .handle_refreshes(&mut self.routing_node, src_name, refreshes)
                }
            },
            (
                Authority::ManagedNode(src_name),
                Authority::NaeManager(_),
                Request::Refresh(serialised_msg, _),
            ) => self.data_manager.handle_serialised_refresh(
                &mut self.routing_node,
                src_name,
                &serialised_msg,
            ),
            (
                Authority::NaeManager(_),
                Authority::NaeManager(_),
                Request::Refresh(serialised_msg, _),
            ) => self
                .data_manager
                .handle_group_refresh(&mut self.routing_node, serialised_msg),
            // ========== GetAccountInfo ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::GetAccountInfo(msg_id),
            ) => self.maid_manager.handle_get_account_info(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                msg_id,
            ),
            // ========== GetIData ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::GetIData { name, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::GetIData { name, msg_id },
            ) => self
                .data_manager
                .handle_get_idata(&mut self.routing_node, src, dst, name, msg_id),
            // ========== PutIData ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::PutIData { data, msg_id },
            ) => self.maid_manager.handle_put_idata(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                data,
                msg_id,
            ),
            (
                Authority::ClientManager(_),
                Authority::NaeManager(_),
                Request::PutIData { data, msg_id },
            ) => self
                .data_manager
                .handle_put_idata(&mut self.routing_node, src, dst, data, msg_id),
            // ========== PutMData ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::PutMData {
                    data,
                    msg_id,
                    requester,
                },
            ) => self.maid_manager.handle_put_mdata(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                data,
                msg_id,
                requester,
            ),
            (
                Authority::ClientManager(_),
                Authority::NaeManager(_),
                Request::PutMData {
                    data,
                    msg_id,
                    requester,
                },
            ) => self.data_manager.handle_put_mdata(
                &mut self.routing_node,
                src,
                dst,
                data,
                msg_id,
                requester,
            ),
            // ========== GetMData ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::GetMData { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::NaeManager(_),
                Request::GetMData { name, tag, msg_id },
            ) => self
                .data_manager
                .handle_get_mdata(&mut self.routing_node, src, name, tag, msg_id),
            // ========== GetMDataShell ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::GetMDataShell { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::GetMDataShell { name, tag, msg_id },
            ) => self.data_manager.handle_get_mdata_shell(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== GetMDataVersion ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::GetMDataVersion { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::GetMDataVersion { name, tag, msg_id },
            ) => self.data_manager.handle_get_mdata_version(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== ListMDataEntries ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::ListMDataEntries { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::ListMDataEntries { name, tag, msg_id },
            ) => self.data_manager.handle_list_mdata_entries(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== ListMDataKeys ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::ListMDataKeys { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::ListMDataKeys { name, tag, msg_id },
            ) => self.data_manager.handle_list_mdata_keys(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== ListMDataValues ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::ListMDataValues { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::ListMDataValues { name, tag, msg_id },
            ) => self.data_manager.handle_list_mdata_values(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== GetMDataValue ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::GetMDataValue {
                    name,
                    tag,
                    key,
                    msg_id,
                },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::GetMDataValue {
                    name,
                    tag,
                    key,
                    msg_id,
                },
            ) => self.data_manager.handle_get_mdata_value(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                key,
                msg_id,
            ),
            // ========== MutateMDataEntries ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::MutateMDataEntries {
                    name,
                    tag,
                    actions,
                    msg_id,
                    requester,
                },
            ) => self.maid_manager.handle_mutate_mdata_entries(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                name,
                tag,
                actions,
                msg_id,
                requester,
            ),
            (
                Authority::ClientManager(_),
                Authority::NaeManager(_),
                Request::MutateMDataEntries {
                    name,
                    tag,
                    actions,
                    msg_id,
                    requester,
                },
            ) => self.data_manager.handle_mutate_mdata_entries(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                actions,
                msg_id,
                requester,
            ),
            // ========== ListMDataPermissions ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::ListMDataPermissions { name, tag, msg_id },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::ListMDataPermissions { name, tag, msg_id },
            ) => self.data_manager.handle_list_mdata_permissions(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                msg_id,
            ),
            // ========== ListMDataUserPermissions ==========
            (
                Authority::Client { .. },
                Authority::NaeManager(_),
                Request::ListMDataUserPermissions {
                    name,
                    tag,
                    user,
                    msg_id,
                },
            )
            | (
                Authority::ManagedNode(_),
                Authority::ManagedNode(_),
                Request::ListMDataUserPermissions {
                    name,
                    tag,
                    user,
                    msg_id,
                },
            ) => self.data_manager.handle_list_mdata_user_permissions(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                user,
                msg_id,
            ),
            // ========== SetMDataUserPermissions ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::SetMDataUserPermissions {
                    name,
                    tag,
                    user,
                    permissions,
                    version,
                    msg_id,
                    requester,
                },
            ) => self.maid_manager.handle_set_mdata_user_permissions(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                name,
                tag,
                user,
                permissions,
                version,
                msg_id,
                requester,
            ),
            (
                Authority::ClientManager(_),
                Authority::NaeManager(_),
                Request::SetMDataUserPermissions {
                    name,
                    tag,
                    user,
                    permissions,
                    version,
                    msg_id,
                    requester,
                },
            ) => self.data_manager.handle_set_mdata_user_permissions(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                user,
                permissions,
                version,
                msg_id,
                requester,
            ),
            // ========== DelMDataUserPermissions ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::DelMDataUserPermissions {
                    name,
                    tag,
                    user,
                    version,
                    msg_id,
                    requester,
                },
            ) => self.maid_manager.handle_del_mdata_user_permissions(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                name,
                tag,
                user,
                version,
                msg_id,
                requester,
            ),
            (
                Authority::ClientManager(_),
                Authority::NaeManager(_),
                Request::DelMDataUserPermissions {
                    name,
                    tag,
                    user,
                    version,
                    msg_id,
                    requester,
                },
            ) => self.data_manager.handle_del_mdata_user_permissions(
                &mut self.routing_node,
                src,
                dst,
                name,
                tag,
                user,
                version,
                msg_id,
                requester,
            ),
            // ========== ChangeMDataOwner ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::ChangeMDataOwner {
                    name,
                    tag,
                    new_owners,
                    version,
                    msg_id,
                },
            ) => self.maid_manager.handle_change_mdata_owner(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                name,
                tag,
                new_owners,
                version,
                msg_id,
            ),
            (
                Authority::ClientManager(src_name),
                Authority::NaeManager(_),
                Request::ChangeMDataOwner {
                    name,
                    tag,
                    new_owners,
                    version,
                    msg_id,
                },
            ) => self.data_manager.handle_change_mdata_owner(
                &mut self.routing_node,
                ClientManagerAuthority(src_name),
                dst,
                name,
                tag,
                new_owners,
                version,
                msg_id,
            ),
            // ========== ListAuthKeysAndVersion ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::ListAuthKeysAndVersion(msg_id),
            ) => self.maid_manager.handle_list_auth_keys_and_version(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                msg_id,
            ),
            // ========== InsAuthKey ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::InsAuthKey {
                    key,
                    version,
                    msg_id,
                },
            ) => self.maid_manager.handle_ins_auth_key(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                key,
                version,
                msg_id,
            ),
            // ========== DelAuthKey ==========
            (
                Authority::Client {
                    client_id,
                    proxy_node_name,
                },
                Authority::ClientManager(dst_name),
                Request::DelAuthKey {
                    key,
                    version,
                    msg_id,
                },
            ) => self.maid_manager.handle_del_auth_key(
                &mut self.routing_node,
                ClientAuthority {
                    client_id,
                    proxy_node_name,
                },
                ClientManagerAuthority(dst_name),
                key,
                version,
                msg_id,
            ),

            // ========== Invalid Request ==========
            (_, _, request) => Err(InternalError::UnknownRequestType(request)),
        }
    }

    fn on_response(
        &mut self,
        response: Response,
        src: Authority<XorName>,
        dst: Authority<XorName>,
    ) -> Result<(), InternalError> {
        match (src, dst, response) {
            // ================== GetIData success ==================
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetIData { res: Ok(data), .. },
            ) => self
                .data_manager
                .handle_get_idata_success(&mut self.routing_node, src_name, data),
            // ================== GetIData failure ==================
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetIData { res: Err(_), .. },
            ) => self
                .data_manager
                .handle_get_idata_failure(&mut self.routing_node, src_name),
            // ================== PutIData ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::PutIData { res, msg_id },
            ) => self
                .maid_manager
                .handle_put_idata_response(&mut self.routing_node, res, msg_id),
            // ================== PutMData ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::PutMData { res, msg_id },
            ) => self
                .maid_manager
                .handle_put_mdata_response(&mut self.routing_node, res, msg_id),
            // ================== GetMData success =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMData {
                    res: Ok(data),
                    msg_id,
                },
            ) => self.data_manager.handle_get_mdata_success(
                &mut self.routing_node,
                src_name,
                data,
                msg_id,
            ),
            // ================== GetMData failure =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMData {
                    res: Err(_),
                    msg_id,
                },
            ) => {
                self.data_manager
                    .handle_get_mdata_failure(&mut self.routing_node, src_name, msg_id)
            }
            // ================== GetMDataShell success =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMDataShell { res: Ok(shell), .. },
            ) => self.data_manager.handle_get_mdata_shell_success(
                &mut self.routing_node,
                src_name,
                shell,
            ),
            // ================== GetMDataShell failure =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMDataShell { res: Err(_), .. },
            ) => self
                .data_manager
                .handle_get_mdata_shell_failure(&mut self.routing_node, src_name),
            // ================== GetMDataValue success =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMDataValue { res: Ok(value), .. },
            ) => self.data_manager.handle_get_mdata_value_success(
                &mut self.routing_node,
                src_name,
                value,
            ),
            // ================== GetMDataValue failure =============
            (
                Authority::ManagedNode(src_name),
                Authority::ManagedNode(_),
                Response::GetMDataValue { res: Err(_), .. },
            ) => self
                .data_manager
                .handle_get_mdata_value_failure(&mut self.routing_node, src_name),
            // ================== MutateMDataEntries ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::MutateMDataEntries { res, msg_id },
            ) => self.maid_manager.handle_mutate_mdata_entries_response(
                &mut self.routing_node,
                res,
                msg_id,
            ),
            // ================== SetMDataUserPermissions ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::SetMDataUserPermissions { res, msg_id },
            ) => self
                .maid_manager
                .handle_set_mdata_user_permissions_response(&mut self.routing_node, res, msg_id),
            // ================== DelMDataUserPermissions ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::DelMDataUserPermissions { res, msg_id },
            ) => self
                .maid_manager
                .handle_del_mdata_user_permissions_response(&mut self.routing_node, res, msg_id),
            // ================== ChangeMDataOwner ==================
            (
                Authority::NaeManager(_),
                Authority::ClientManager(_),
                Response::ChangeMDataOwner { res, msg_id },
            ) => self.maid_manager.handle_change_mdata_owner_response(
                &mut self.routing_node,
                res,
                msg_id,
            ),
            // ================== Invalid Response ==================
            (_, _, response) => Err(InternalError::UnknownResponseType(response)),
        }
    }

    fn on_node_added(
        &mut self,
        node_added: XorName,
        routing_table: RoutingTable<XorName>,
    ) -> Result<(), InternalError> {
        self.maid_manager
            .handle_node_added(&mut self.routing_node, &node_added, &routing_table)?;
        self.data_manager
            .handle_node_added(&mut self.routing_node, &node_added, &routing_table)?;
        Ok(())
    }

    fn on_node_lost(
        &mut self,
        node_lost: XorName,
        routing_table: RoutingTable<XorName>,
    ) -> Result<(), InternalError> {
        self.maid_manager
            .handle_node_lost(&mut self.routing_node, &node_lost, &routing_table)?;
        self.data_manager
            .handle_node_lost(&mut self.routing_node, &node_lost, &routing_table)?;
        Ok(())
    }
}

#[cfg(feature = "use-mock-crust")]
impl Vault {
    /// Allow construct vault with config for mock-crust tests.
    pub fn new_with_configs(
        first_vault: bool,
        use_cache: bool,
        config: Config,
        routing_config: RoutingConfig,
    ) -> Result<Self, InternalError> {
        Self::vault_with_config(
            RoutingNode::builder()
                .first(first_vault)
                .config(routing_config),
            use_cache,
            config,
        )
    }

    /// Non-blocking call to process any events in the event queue, returning true if
    /// any received, otherwise returns false.
    pub fn poll(&mut self) -> bool {
        let mut processed = self.routing_node.poll();

        while let Ok(event) = self.routing_node.try_next_ev() {
            if let EventResult::Processed = self.process_event(event) {
                processed = true;
            }
        }

        processed
    }

    /// Get the IDs and versions of all the data chunks stored in a personas' chunk store.
    pub fn get_stored_ids_and_versions(&self) -> Result<Vec<(DataId, u64)>, ChunkStoreError> {
        self.data_manager.get_stored_ids_and_versions()
    }

    /// Get the number of mutations the network processed for the given client.
    pub fn get_maid_manager_mutation_count(&self, client_name: &XorName) -> Option<u64> {
        self.maid_manager.get_mutation_count(client_name)
    }

    /// Vault node name
    pub fn name(&self) -> XorName {
        *unwrap!(self.routing_node.id()).name()
    }

    /// Vault routing_table
    pub fn routing_table(&self) -> &RoutingTable<XorName> {
        unwrap!(self.routing_node.routing_table())
    }

    /// Set whether `DataManager` group refreshes should be delayed or not on this vault.
    /// Any un-handled delayed group refreshes in the cache will be handled and purged.
    pub fn delay_group_refreshes(&mut self, delayed: bool) {
        self.data_manager
            .delay_group_refreshes(&mut self.routing_node, delayed)
    }
}

// Result of processing an event.
enum EventResult {
    // Event was processed.
    Processed,
    // Event was ignored.
    Ignored,
    // `Terminate` event received.
    Terminate,
    // `RestartRequired` event received.
    Restart,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub enum Refresh {
    MaidManager(maid_manager::Refresh),
    DataManager(Vec<data_manager::Refresh>),
}
