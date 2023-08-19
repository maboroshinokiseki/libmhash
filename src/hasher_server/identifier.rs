use std::{
    borrow::Cow,
    fmt::Display,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Identifier {
    Path(Arc<Path>),
    Name(Arc<str>),
}

impl From<&Path> for Identifier {
    fn from(value: &Path) -> Self {
        Self::Path(value.into())
    }
}

impl From<PathBuf> for Identifier {
    fn from(value: PathBuf) -> Self {
        Self::Path(value.into())
    }
}

impl From<&PathBuf> for Identifier {
    fn from(value: &PathBuf) -> Self {
        Self::Path(value.as_path().into())
    }
}

impl From<Arc<Path>> for Identifier {
    fn from(value: Arc<Path>) -> Self {
        Self::Path(value)
    }
}

impl From<&Arc<Path>> for Identifier {
    fn from(value: &Arc<Path>) -> Self {
        Arc::clone(value).into()
    }
}

impl From<Cow<'_, Path>> for Identifier {
    fn from(value: Cow<'_, Path>) -> Self {
        Arc::<Path>::from(value).into()
    }
}

impl From<&str> for Identifier {
    fn from(value: &str) -> Self {
        Self::Name(value.into())
    }
}

impl From<String> for Identifier {
    fn from(value: String) -> Self {
        Self::Name(value.into())
    }
}

impl From<&String> for Identifier {
    fn from(value: &String) -> Self {
        Self::Name(value.as_str().into())
    }
}

impl From<Arc<str>> for Identifier {
    fn from(value: Arc<str>) -> Self {
        Self::Name(value)
    }
}

impl From<&Arc<str>> for Identifier {
    fn from(value: &Arc<str>) -> Self {
        Arc::clone(value).into()
    }
}

impl From<Cow<'_, str>> for Identifier {
    fn from(value: Cow<'_, str>) -> Self {
        Arc::<str>::from(value).into()
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Identifier::Path(path) => write!(f, "{}", path.to_string_lossy()),
            Identifier::Name(name) => write!(f, "{}", name),
        }
    }
}
