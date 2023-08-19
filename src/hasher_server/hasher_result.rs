use std::{fmt::Debug, hash::Hash};

use crate::{
    hasher_server::{hasher_wrapper::HasherWrapper, Identifier},
    paranoid_hash::Hasher,
};

pub struct HasherResult<'a, Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub identifier: Identifier,
    pub tag: Tag,
    pub hasher: &'a dyn Hasher,
}

impl<'a> std::fmt::Debug for dyn Hasher + 'a {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x?}", self.digest())
    }
}

impl<'a, Tag> Debug for HasherResult<'a, Tag>
where
    Tag: Clone + Eq + Hash + Send + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HasherResult")
            .field("identifier", &self.identifier)
            .field("tag", &self.tag)
            .field("hasher", &self.hasher)
            .finish()
    }
}

pub(super) struct HasherResultPrivate<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub identifier: Identifier,
    pub hasher_wrapper: HasherWrapper<Tag>,
}
