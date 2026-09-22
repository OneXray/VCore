use thiserror::Error;

pub type Result<T> = std::result::Result<T, VCoreError>;

#[derive(Debug, Error)]
pub enum VCoreError {
    #[error("invalid lifecycle transition from {from} to {to}")]
    InvalidLifecycleTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("invalid packet: {0}")]
    InvalidPacket(&'static str),

    #[error("resource limit exceeded: {resource} (limit {limit})")]
    ResourceLimit {
        resource: &'static str,
        limit: usize,
    },

    #[error("platform operation failed: {0}")]
    Platform(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
