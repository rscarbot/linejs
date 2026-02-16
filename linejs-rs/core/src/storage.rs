use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose};
use std::path::Path;

use crate::e2ee::E2EEKeyData;

/// Serializable E2EE key for persistent storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedE2EEKey {
    pub key_id: String,
    pub priv_key_b64: String,
    pub pub_key_b64: String,
    pub e2ee_version: String,
}

impl SavedE2EEKey {
    pub fn from_key_data(key_data: &E2EEKeyData) -> Self {
        Self {
            key_id: key_data.key_id.clone(),
            priv_key_b64: general_purpose::STANDARD.encode(&key_data.priv_key),
            pub_key_b64: general_purpose::STANDARD.encode(&key_data.pub_key),
            e2ee_version: key_data.e2ee_version.clone(),
        }
    }

    pub fn to_key_data(&self) -> Result<E2EEKeyData, String> {
        let priv_key = general_purpose::STANDARD.decode(&self.priv_key_b64)
            .map_err(|e| format!("decode priv_key: {}", e))?;
        let pub_key = general_purpose::STANDARD.decode(&self.pub_key_b64)
            .map_err(|e| format!("decode pub_key: {}", e))?;
        Ok(E2EEKeyData {
            key_id: self.key_id.clone(),
            priv_key,
            pub_key,
            e2ee_version: self.e2ee_version.clone(),
        })
    }
}

/// Persistent credential storage (JSON file), mirroring TypeScript's FileStorage/kvTypes.
/// Stores: auth_token, qr_cert (for PIN-less re-login), mid, and E2EE key data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Credential {
    pub auth_token: Option<String>,
    pub qr_cert: Option<String>,
    pub mid: Option<String>,
    pub e2ee_key: Option<SavedE2EEKey>,
}

impl Credential {
    /// Load credentials from a JSON file. Returns default if file doesn't exist.
    pub fn load(path: &str) -> Self {
        if !Path::new(path).exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save credentials to a JSON file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize credentials: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("write credentials: {}", e))?;
        Ok(())
    }

    /// Check if we have a valid auth token saved
    pub fn has_auth_token(&self) -> bool {
        self.auth_token.as_ref().map_or(false, |t| !t.is_empty())
    }

    /// Check if we have a saved QR certificate
    pub fn has_qr_cert(&self) -> bool {
        self.qr_cert.as_ref().map_or(false, |c| !c.is_empty())
    }

    /// Get E2EE key data if available
    pub fn get_e2ee_key(&self) -> Option<E2EEKeyData> {
        self.e2ee_key.as_ref().and_then(|k| k.to_key_data().ok())
    }
}
