use std::hash::Hash;

use crate::hasher_server::Identifier;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct HasherProgress<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub identifier: Identifier,
    pub tag: Tag,
    pub total_data_length: u64,
    pub processed_data_length: u64,
}
