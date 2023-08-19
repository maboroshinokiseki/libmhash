use std::{hash::Hash, sync::Arc};

use crate::hasher_server::{
    data_wrapper::DataWrapper, hasher_result::HasherResultPrivate, hasher_wrapper::HasherWrapper,
    HasherError, HasherProgress, Identifier,
};

pub(super) enum Operation<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    NewIdentifier {
        identifier: Identifier,
        hashers: Vec<HasherWrapper<Tag>>,
    },
    EndOfNewIdentifier,
    Data(Arc<DataWrapper>),
    Progress(HasherProgress<Tag>),
    Result(HasherResultPrivate<Tag>),
    Error(HasherError<Tag>),
}
