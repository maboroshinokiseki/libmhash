macro_rules! unwrap_or {
    ( $e:expr, $identifier:expr, $tag:expr, $sender:expr, $s:stmt) => {
        match $e {
            Ok(x) => x,
            Err(e) => {
                $sender
                    .send(Operation::Error(HasherError {
                        identifier: $identifier,
                        tag: $tag,
                        error: e.into(),
                    }))
                    .unwrap();
                $s
            }
        }
    };
}

macro_rules! unwrap_or_break {
    ( $e:expr, $i:expr, $t:expr, $s:expr) => {
        unwrap_or!($e, $i, $t, $s, break)
    };
}

macro_rules! unwrap_or_return {
    ( $e:expr, $i:expr, $t:expr, $s:expr) => {
        unwrap_or!($e, $i, $t, $s, return)
    };
}
