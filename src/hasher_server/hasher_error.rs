use std::hash::Hash;

use crate::{hasher_server::Identifier, Error};

#[derive(Debug)]
pub struct HasherError<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub identifier: Identifier,
    pub tag: Option<Tag>,
    pub error: Error,
}
