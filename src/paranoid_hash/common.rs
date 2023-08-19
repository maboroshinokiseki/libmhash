#![macro_use]

macro_rules! add {
    ("wrapping", $left:expr, $right:expr, $count_type:ty) => {
        $left = $left.wrapping_add($right.wrapping_mul(8));
    };
    ("checked", $left:expr, $right:expr, $count_type:ty) => {
        $left = $right
            .checked_mul(8)
            .and_then(|i| i.checked_add($left))
            .ok_or(Error::DataLengthOverflowed(<$count_type>::MAX as u128))?;
    };
}

macro_rules! from_bytes {
    ("le", $word_type:ty, $data:expr) => {
        <$word_type>::from_le_bytes($data)
    };
    ("be", $word_type:ty, $data:expr) => {
        <$word_type>::from_be_bytes($data)
    };
}

macro_rules! to_bytes {
    ("le", $data:expr) => {
        $data.to_le_bytes()
    };
    ("be", $data:expr) => {
        $data.to_be_bytes()
    };
}

#[macro_export]
macro_rules! transmute_update {
    ( $self:expr, $data:expr, $block_size:expr, $word_type:ty, $count_type:ty, $add_mode:tt, $endian:tt ) => {
        use $crate::Error;

        if $self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        if $data.len() % $block_size != 0 {
            return Err(Error::DataLengthMismatched($data.len(), $block_size));
        }

        add!(
            $add_mode,
            $self.count,
            $data.len() as $count_type,
            $count_type
        );

        use $crate::paranoid_hash::hash_helper::slice_as_chunks;

        let block_chunks: &[[u8; $block_size]] = slice_as_chunks($data);

        for block_chunk in block_chunks {
            let value_chunks: &[[u8; size_of::<$word_type>()]] = slice_as_chunks(block_chunk);

            let mut temp_block = [0; $block_size / size_of::<$word_type>()];
            for (value, value_chunk) in temp_block.iter_mut().zip(value_chunks.iter()) {
                *value = from_bytes!($endian, $word_type, *value_chunk);
            }

            $self.update_block(&temp_block);
        }

        return Ok(());
    };
}

#[macro_export]
macro_rules! transmute_update_last {
    ( $self:expr, $data:expr, $block_size:expr, $word_type:ty, $count_type:ty, $add_mode:tt, $endian:tt ) => {
        const PADDING: u8 = 0b1000_0000;
        const PADDING_LENGTH: usize = 1;

        use $crate::Error;

        if $self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        if $data.len() > $block_size {
            return Err(Error::DataTooLarge($data.len(), $block_size));
        }

        add!(
            $add_mode,
            $self.count,
            $data.len() as $count_type,
            $count_type
        );

        let mut final_block = [0u8; $block_size * 2];
        final_block[0..$data.len()].clone_from_slice($data);
        final_block[$data.len()] = PADDING;

        let count = to_bytes!($endian, $self.count);

        let final_block_slice = if $data.len() + count.len() + PADDING_LENGTH <= $block_size {
            final_block[$block_size - count.len()..$block_size].clone_from_slice(&count);
            &final_block[0..$block_size]
        } else {
            let length = final_block.len();
            final_block[length - count.len()..].clone_from_slice(&count);
            &final_block[..]
        };

        $self.update(final_block_slice)?;

        let digest_chunks: &mut [[u8; std::mem::size_of::<$word_type>()]] =
            $crate::paranoid_hash::hash_helper::slice_as_chunks_mut(&mut $self.digest);
        for (d, s) in digest_chunks.iter_mut().zip($self.state.iter()) {
            d.clone_from_slice(&to_bytes!($endian, s));
        }

        $self.is_done = true;

        return Ok(());
    };
}
