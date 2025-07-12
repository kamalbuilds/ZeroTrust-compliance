//! Configuration management for the ZeroTrust Compliance Backend

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    
    /// Database configuration
    pub database: DatabaseConfig,
    
    /// Miden client configuration
    pub miden: MidenConfig,
    
    /// Compliance configuration
    pub compliance: ComplianceConfig,
    
    /// Webhook configuration
    pub webhooks: WebhookConfig,
    
    /// Security configuration
    pub security: SecurityConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    
    /// Server port
    pub port: u16,
    
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    
    /// Request timeout in seconds
    pub request_timeout: u64,
    
    /// CORS configuration
    pub cors: CorsConfig,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    
    /// Max age for preflight requests
    pub max_age: u64,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    
    /// Maximum number of connections
    pub max_connections: u32,
    
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    
    /// Idle timeout in seconds
    pub idle_timeout: u64,
    
    /// Run migrations on startup
    pub run_migrations: bool,
}

/// Miden client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidenConfig {
    /// Miden node RPC endpoint
    pub rpc_endpoint: String,
    
    /// Store path for the Miden client
    pub store_path: PathBuf,
    
    /// Keystore path
    pub keystore_path: PathBuf,
    
    /// Remote prover endpoint (optional)
    pub remote_prover_endpoint: Option<String>,
    
    /// Enable debug mode
    pub debug_mode: bool,
    
    /// Maximum number of accounts to track
    pub max_accounts: u32,
    
    /// Sync interval in seconds
    pub sync_interval: u64,
    
    /// Transaction timeout in seconds
    pub transaction_timeout: u64,
    
    /// Enable delegated proving
    pub enable_delegated_proving: bool,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// KYC configuration
    pub kyc: KycConfig,
    
    /// AML configuration
    pub aml: AmlConfig,
    
    /// Sanctions screening configuration
    pub sanctions: SanctionsConfig,
    
    /// Attestation configuration
    pub attestation: AttestationConfig,
}

/// KYC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KycConfig {
    /// Enable KYC verification
    pub enabled: bool,
    
    /// KYC provider API endpoint
    pub provider_endpoint: Option<String>,
    
    /// KYC provider API key
    pub provider_api_key: Option<String>,
    
    /// Verification timeout in seconds
    pub verification_timeout: u64,
    
    /// Minimum document quality score
    pub min_quality_score: f64,
    
    /// Supported document types
    pub supported_documents: Vec<String>,
    
    /// Verification expiry in days
    pub verification_expiry_days: u32,
}

/// AML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlConfig {
    /// Enable AML screening
    pub enabled: bool,
    
    /// AML provider API endpoint
    pub provider_endpoint: Option<String>,
    
    /// AML provider API key
    pub provider_api_key: Option<String>,
    
    /// Risk assessment timeout in seconds
    pub assessment_timeout: u64,
    
    /// Risk thresholds
    pub risk_thresholds: RiskThresholds,
    
    /// Transaction monitoring settings
    pub transaction_monitoring: TransactionMonitoringConfig,
}

/// Risk thresholds for AML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Low risk threshold
    pub low: f64,
    
    /// Medium risk threshold
    pub medium: f64,
    
    /// High risk threshold
    pub high: f64,
}

/// Transaction monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMonitoringConfig {
    /// Maximum transaction amount for low risk
    pub max_amount_low_risk: u64,
    
    /// Maximum transaction amount for medium risk
    pub max_amount_medium_risk: u64,
    
    /// Maximum daily transaction count
    pub max_daily_transactions: u32,
    
    /// Suspicious pattern detection
    pub enable_pattern_detection: bool,
}

/// Sanctions screening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsConfig {
    /// Enable sanctions screening
    pub enabled: bool,
    
    /// Sanctions list provider
    pub provider_endpoint: Option<String>,
    
    /// Sanctions list API key
    pub provider_api_key: Option<String>,
    
    /// Screening timeout in seconds
    pub screening_timeout: u64,
    
    /// Sanctions list update interval in hours
    pub update_interval_hours: u32,
    
    /// Fuzzy matching threshold
    pub fuzzy_match_threshold: f64,
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Attestation validity period in days
    pub validity_period_days: u32,
    
    /// Enable proof verification
    pub enable_proof_verification: bool,
    
    /// Proof verification timeout in seconds
    pub proof_verification_timeout: u64,
    
    /// Maximum proof size in bytes
    pub max_proof_size: usize,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Enable webhooks
    pub enabled: bool,
    
    /// Webhook timeout in seconds
    pub timeout: u64,
    
    /// Maximum retry attempts
    pub max_retries: u32,
    
    /// Retry delay in seconds
    pub retry_delay: u64,
    
    /// Webhook secret for signature verification
    pub secret: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// API key length
    pub api_key_length: usize,
    
    /// JWT secret
    pub jwt_secret: String,
    
    /// JWT expiry in seconds
    pub jwt_expiry: u64,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    
    /// Enable API key authentication
    pub enable_api_key_auth: bool,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute
    pub requests_per_minute: u32,
    
    /// Requests per hour
    pub requests_per_hour: u32,
    
    /// Requests per day
    pub requests_per_day: u32,
    
    /// Burst size
    pub burst_size: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    
    /// Log format (json or text)
    pub format: String,
    
    /// Enable request logging
    pub log_requests: bool,
    
    /// Enable response logging
    pub log_responses: bool,
    
    /// Log file path (optional)
    pub log_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            miden: MidenConfig::default(),
            compliance: ComplianceConfig::default(),
            webhooks: WebhookConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            max_body_size: 10 * 1024 * 1024, // 10MB
            request_timeout: 30,
            cors: CorsConfig::default(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
            allowed_headers: vec!["*".to_string()],
            max_age: 3600,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/compliance".to_string(),
            max_connections: 20,
            connection_timeout: 30,
            idle_timeout: 600,
            run_migrations: true,
        }
    }
}

impl Default for MidenConfig {
    fn default() -> Self {
        Self {
            rpc_endpoint: "https://testnet-rpc.miden.io".to_string(),
            store_path: PathBuf::from("./miden_store.sqlite3"),
            keystore_path: PathBuf::from("./miden_keystore"),
            remote_prover_endpoint: None,
            debug_mode: false,
            max_accounts: 1000,
            sync_interval: 30,
            transaction_timeout: 60,
            enable_delegated_proving: false,
        }
    }
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            kyc: KycConfig::default(),
            aml: AmlConfig::default(),
            sanctions: SanctionsConfig::default(),
            attestation: AttestationConfig::default(),
        }
    }
}

impl Default for KycConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider_endpoint: None,
            provider_api_key: None,
            verification_timeout: 300,
            min_quality_score: 0.85,
            supported_documents: vec!["passport".to_string(), "driver_license".to_string(), "national_id".to_string()],
            verification_expiry_days: 365,
        }
    }
}

impl Default for AmlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider_endpoint: None,
            provider_api_key: None,
            assessment_timeout: 60,
            risk_thresholds: RiskThresholds::default(),
            transaction_monitoring: TransactionMonitoringConfig::default(),
        }
    }
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            low: 0.3,
            medium: 0.7,
            high: 0.9,
        }
    }
}

impl Default for TransactionMonitoringConfig {
    fn default() -> Self {
        Self {
            max_amount_low_risk: 1000,
            max_amount_medium_risk: 10000,
            max_daily_transactions: 100,
            enable_pattern_detection: true,
        }
    }
}

impl Default for SanctionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider_endpoint: None,
            provider_api_key: None,
            screening_timeout: 30,
            update_interval_hours: 24,
            fuzzy_match_threshold: 0.8,
        }
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            validity_period_days: 90,
            enable_proof_verification: true,
            proof_verification_timeout: 120,
            max_proof_size: 1024 * 1024, // 1MB
        }
    }
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: 30,
            max_retries: 3,
            retry_delay: 5,
            secret: "default_webhook_secret".to_string(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            api_key_length: 32,
            jwt_secret: "default_jwt_secret".to_string(),
            jwt_expiry: 3600,
            rate_limiting: RateLimitConfig::default(),
            enable_api_key_auth: true,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            requests_per_hour: 1000,
            requests_per_day: 10000,
            burst_size: 10,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            log_requests: true,
            log_responses: false,
            log_file: None,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("COMPLIANCE"))
            .build()?;
        
        settings.try_deserialize()
    }
    
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("COMPLIANCE"))
            .build()?;
        
        settings.try_deserialize()
    }
} 