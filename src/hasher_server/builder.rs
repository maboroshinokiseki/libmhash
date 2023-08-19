use std::{fmt::Debug, hash::Hash, marker::PhantomData, sync::Arc};

use crate::{
    hasher_server::{HasherError, HasherProgress, HasherResult, HasherServer},
    simple_semaphore::SimpleSemaphore,
};

#[derive(Clone, Copy)]
pub struct Builder<Tag, P = (), R = (), E = ()> {
    id_count: usize,
    block_count: usize,
    block_size: usize,
    progress_callback: Option<P>,
    result_callback: Option<R>,
    error_callback: Option<E>,

    marker: PhantomData<Tag>,
}

impl<Tag> Builder<Tag>
where
    Tag: Clone + Eq + Hash + Send + 'static,
{
    pub fn new() -> Builder<
        Tag,
        impl FnMut(&HasherProgress<Tag>),
        impl FnMut(&HasherResult<Tag>),
        impl FnMut(&HasherError<Tag>),
    > {
        let mut temp = Builder {
            id_count: 0,
            block_count: 0,
            block_size: 0,
            progress_callback: Some(empty_progress_callback),
            result_callback: Some(empty_result_callback),
            error_callback: Some(empty_error_callback),
            marker: PhantomData,
        };

        temp.progress_callback = None;
        temp.result_callback = None;
        temp.error_callback = None;

        temp
    }
}

impl<Tag, P, R, E> Builder<Tag, P, R, E> {
    const DEFAULT_BLOCK_COUNT: usize = 2;
    const DEFAULT_ID_COUNT: usize = 1;
}

pub trait BuilderTrait {
    const BASE_BLOCK_SIZE: usize;

    type Tag: Clone + Eq + Hash + Send;
    type ProgressCallback: FnMut(&HasherProgress<Self::Tag>);
    type ResultCallback: FnMut(&HasherResult<Self::Tag>);
    type ErrorCallback: FnMut(&HasherError<Self::Tag>);

    fn identifier_count(self, id_count: usize) -> Self;

    fn block_count(self, block_count: usize) -> Self;

    fn block_size(self, block_size: usize) -> Self;

    fn approximate_block_size(self, block_size: usize) -> Self;

    fn on_progress<F: FnMut(&HasherProgress<Self::Tag>)>(
        self,
        progress_callback: Option<F>,
    ) -> Builder<Self::Tag, F, Self::ResultCallback, Self::ErrorCallback>;

    fn on_result<F: FnMut(&HasherResult<Self::Tag>)>(
        self,
        result_callback: Option<F>,
    ) -> Builder<Self::Tag, Self::ProgressCallback, F, Self::ErrorCallback>;

    fn on_error<F: FnMut(&HasherError<Self::Tag>)>(
        self,
        error_callback: Option<F>,
    ) -> Builder<Self::Tag, Self::ProgressCallback, Self::ResultCallback, F>;

    #[allow(clippy::type_complexity)]
    fn build(
        self,
    ) -> crate::Result<
        HasherServer<Self::Tag, Self::ProgressCallback, Self::ResultCallback, Self::ErrorCallback>,
    >;
}

impl<Tag, P, R, E> BuilderTrait for Builder<Tag, P, R, E>
where
    Tag: Clone + Eq + Hash + Send,
    P: FnMut(&HasherProgress<Tag>),
    R: FnMut(&HasherResult<Tag>),
    E: FnMut(&HasherError<Tag>),
{
    const BASE_BLOCK_SIZE: usize = 128;

    type Tag = Tag;

    type ProgressCallback = P;

    type ResultCallback = R;

    type ErrorCallback = E;

    fn identifier_count(self, id_count: usize) -> Self {
        Self { id_count, ..self }
    }

    fn block_count(self, block_count: usize) -> Self {
        Self {
            block_count,
            ..self
        }
    }

    fn block_size(self, block_size: usize) -> Self {
        Self { block_size, ..self }
    }

    fn approximate_block_size(self, block_size: usize) -> Self {
        let block_size = match block_size / Self::BASE_BLOCK_SIZE * Self::BASE_BLOCK_SIZE {
            0 => Self::BASE_BLOCK_SIZE,
            others => others,
        };

        Self { block_size, ..self }
    }

    fn on_progress<F: FnMut(&HasherProgress<Tag>)>(
        self,
        progress_callback: Option<F>,
    ) -> Builder<Tag, F, R, E> {
        Builder {
            id_count: self.id_count,
            block_count: self.block_count,
            block_size: self.block_size,
            progress_callback,
            result_callback: self.result_callback,
            error_callback: self.error_callback,
            marker: PhantomData,
        }
    }

    fn on_result<F: FnMut(&HasherResult<Tag>)>(
        self,
        result_callback: Option<F>,
    ) -> Builder<Tag, P, F, E> {
        Builder {
            id_count: self.id_count,
            block_count: self.block_count,
            block_size: self.block_size,
            progress_callback: self.progress_callback,
            result_callback,
            error_callback: self.error_callback,
            marker: PhantomData,
        }
    }

    fn on_error<F: FnMut(&HasherError<Tag>)>(
        self,
        error_callback: Option<F>,
    ) -> Builder<Tag, P, R, F> {
        Builder {
            id_count: self.id_count,
            block_count: self.block_count,
            block_size: self.block_size,
            progress_callback: self.progress_callback,
            result_callback: self.result_callback,
            error_callback,
            marker: PhantomData,
        }
    }

    fn build(self) -> crate::Result<HasherServer<Tag, P, R, E>> {
        let block_size = match self.block_size {
            0 => Self::BASE_BLOCK_SIZE,
            others => others,
        };
        if block_size % Self::BASE_BLOCK_SIZE != 0 {
            return Err(crate::Error::IncorrectBlockSize);
        }
        let minimum_block_size = Self::BASE_BLOCK_SIZE;

        //floor block size
        let block_size = match self.block_size / minimum_block_size * minimum_block_size {
            0 => minimum_block_size,
            others => others,
        };

        let block_count = match self.block_count {
            0 => Self::DEFAULT_BLOCK_COUNT,
            others => others,
        };

        let id_count = match self.id_count {
            0 => Self::DEFAULT_ID_COUNT,
            others => others,
        };

        let id_semaphore = Arc::new(SimpleSemaphore::new(id_count));

        let operation_channel = crossbeam_channel::unbounded();

        let progress_callback = self.progress_callback;
        let result_callback = self.result_callback;
        let error_callback = self.error_callback;

        Ok(HasherServer {
            operation_channel,
            block_size,
            block_count,
            id_count,
            id_semaphore,
            progress_callback,
            result_callback,
            error_callback,
        })
    }
}

impl<Tag, P, R, E> Debug for Builder<Tag, P, R, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("id_count", &self.id_count)
            .field("block_count", &self.block_count)
            .field("block_size", &self.block_size)
            .field(
                "progress_callback",
                match &self.progress_callback {
                    Some(_) => &"Some { .. }",
                    None => &"None",
                },
            )
            .field(
                "result_callback",
                match &self.result_callback {
                    Some(_) => &"Some { .. }",
                    None => &"None",
                },
            )
            .field(
                "error_callback",
                match &self.error_callback {
                    Some(_) => &"Some { .. }",
                    None => &"None",
                },
            )
            .field("marker", &self.marker)
            .finish()
    }
}

fn empty_progress_callback<Tag: Clone + Eq + Hash + Send>(_: &HasherProgress<Tag>) {}

fn empty_result_callback<Tag: Clone + Eq + Hash + Send>(_: &HasherResult<Tag>) {}

fn empty_error_callback<Tag: Clone + Eq + Hash + Send>(_: &HasherError<Tag>) {}
