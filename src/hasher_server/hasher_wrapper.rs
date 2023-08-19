use std::{hash::Hash, sync::Arc};

use crate::{
    hasher_server::sync_unsafe_cell::SyncUnsafeCell,
    paranoid_hash::{
        Hasher, HasherTag, CRC32, CRC32C, MD2, MD4, MD5, SHA1, SHA2_224, SHA2_256, SHA2_384,
        SHA2_512, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    },
};

pub struct HasherWrapper<Tag = HasherTag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub(crate) tag: Tag,
    //Same hasher can't be accessed by multiple threads at the same time is guaranteed by the TagThreadPool
    pub(crate) hasher: Arc<SyncUnsafeCell<dyn Hasher>>,
}

impl HasherWrapper {
    pub fn create_from_tag(tag: HasherTag) -> HasherWrapper<HasherTag> {
        match tag {
            HasherTag::CRC32 => HasherWrapper::<HasherTag>::new(tag, CRC32::new()),
            HasherTag::CRC32C => HasherWrapper::<HasherTag>::new(tag, CRC32C::new()),
            HasherTag::MD2 => HasherWrapper::<HasherTag>::new(tag, MD2::new()),
            HasherTag::MD4 => HasherWrapper::<HasherTag>::new(tag, MD4::new()),
            HasherTag::MD5 => HasherWrapper::<HasherTag>::new(tag, MD5::new()),
            HasherTag::SHA1 => HasherWrapper::<HasherTag>::new(tag, SHA1::new()),
            HasherTag::SHA2_224 => HasherWrapper::<HasherTag>::new(tag, SHA2_224::new()),
            HasherTag::SHA2_256 => HasherWrapper::<HasherTag>::new(tag, SHA2_256::new()),
            HasherTag::SHA2_384 => HasherWrapper::<HasherTag>::new(tag, SHA2_384::new()),
            HasherTag::SHA2_512 => HasherWrapper::<HasherTag>::new(tag, SHA2_512::new()),
            HasherTag::SHA3_224 => HasherWrapper::<HasherTag>::new(tag, SHA3_224::new()),
            HasherTag::SHA3_256 => HasherWrapper::<HasherTag>::new(tag, SHA3_256::new()),
            HasherTag::SHA3_384 => HasherWrapper::<HasherTag>::new(tag, SHA3_384::new()),
            HasherTag::SHA3_512 => HasherWrapper::<HasherTag>::new(tag, SHA3_512::new()),
        }
    }
}

impl<Tag> HasherWrapper<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub fn new(tag: Tag, hasher: impl Hasher + 'static) -> HasherWrapper<Tag> {
        HasherWrapper {
            tag,
            hasher: Arc::new(SyncUnsafeCell::new(hasher)),
        }
    }

    pub fn shallow_clone(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            hasher: Arc::clone(&self.hasher),
        }
    }
}
