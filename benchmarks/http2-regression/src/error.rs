use std::fmt::{Display, Formatter};

/// Package-local fail-closed error.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn context(self, context: impl AsRef<str>) -> Self {
        Self::new(format!("{}: {}", context.as_ref(), self.message))
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ResultContext<T> {
    fn context(self, context: impl AsRef<str>) -> Result<T>;
}

impl<T, E> ResultContext<T> for std::result::Result<T, E>
where
    E: Display,
{
    fn context(self, context: impl AsRef<str>) -> Result<T> {
        self.map_err(|error| Error::new(format!("{}: {error}", context.as_ref())))
    }
}
