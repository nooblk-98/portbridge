#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Runtime(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Template(#[from] minijinja::Error),
}

impl AppError {
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }
}
