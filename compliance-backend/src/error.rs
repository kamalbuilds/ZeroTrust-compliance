//! Error handling for the ZeroTrust Compliance Backend

use thiserror::Error;

/// Main error type for the compliance backend
#[derive(Error, Debug)]
pub enum ComplianceError {
    #[error("Miden client error: {0}")]
    MidenClient(#[from] miden_client::ClientError),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Cryptographic error: {message}")]
    Crypto { message: String },
    
    #[error("KYC verification failed: {reason}")]
    KycVerificationFailed { reason: String },
    
    #[error("AML screening failed: {reason}")]
    AmlScreeningFailed { reason: String },
    
    #[error("Sanctions screening failed: {reason}")]
    SanctionsScreeningFailed { reason: String },
    
    #[error("Compliance attestation error: {reason}")]
    ComplianceAttestation { reason: String },
    
    #[error("Account not found: {account_id}")]
    AccountNotFound { account_id: String },
    
    #[error("Insufficient privileges: {required_level:?}")]
    InsufficientPrivileges { required_level: crate::types::ComplianceLevel },
    
    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid API key")]
    InvalidApiKey,
    
    #[error("Webhook delivery failed: {url}")]
    WebhookDeliveryFailed { url: String },
    
    #[error("Transaction execution failed: {reason}")]
    TransactionExecutionFailed { reason: String },
    
    #[error("Account component compilation failed: {reason}")]
    AccountComponentCompilationFailed { reason: String },
    
    #[error("Note script compilation failed: {reason}")]
    NoteScriptCompilationFailed { reason: String },
    
    #[error("Proof generation failed: {reason}")]
    ProofGenerationFailed { reason: String },
    
    #[error("Internal server error: {message}")]
    Internal { message: String },
    
    #[error("Validation error: {field}: {message}")]
    Validation { field: String, message: String },
    
    #[error("Business client not found: {client_id}")]
    BusinessClientNotFound { client_id: String },
    
    #[error("Compliance policy violation: {policy}")]
    CompliancePolicyViolation { policy: String },
    
    #[error("Cross-chain operation failed: {chain}: {reason}")]
    CrossChainOperationFailed { chain: String, reason: String },
    
    #[error("Delegated proving failed: {reason}")]
    DelegatedProvingFailed { reason: String },
}

/// Result type for the compliance backend
pub type Result<T> = std::result::Result<T, ComplianceError>;

impl ComplianceError {
    /// Create a new crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto {
            message: message.into(),
        }
    }
    
    /// Create a new internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
    
    /// Create a new validation error
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
    
    /// Check if the error is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::AccountNotFound { .. }
                | Self::InsufficientPrivileges { .. }
                | Self::InvalidProof { .. }
                | Self::RateLimitExceeded
                | Self::InvalidApiKey
                | Self::Validation { .. }
                | Self::BusinessClientNotFound { .. }
                | Self::CompliancePolicyViolation { .. }
        )
    }
    
    /// Check if the error is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        !self.is_client_error()
    }
    
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::AccountNotFound { .. } | Self::BusinessClientNotFound { .. } => 404,
            Self::InsufficientPrivileges { .. } | Self::InvalidApiKey => 401,
            Self::CompliancePolicyViolation { .. } => 403,
            Self::RateLimitExceeded => 429,
            Self::Validation { .. } => 400,
            Self::InvalidProof { .. } => 400,
            _ => 500,
        }
    }
} 