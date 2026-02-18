use wasm_bindgen::prelude::*;
use linejs_core::device::{DeviceDetails, DeviceType};
use linejs_core::request::RequestClient;
use linejs_core::login::Login;
use linejs_core::service::{TalkService, SyncState};
use linejs_core::e2ee::{E2EE, E2EEKeyData};
use std::collections::HashMap;
use base64::Engine as _;
use base64::engine::general_purpose;

macro_rules! console_log {
    ($($t:tt)*) => {
        web_sys::console::log_1(&format!($($t)*).into())
    }
}

#[wasm_bindgen]
pub struct LineClient {
    device: DeviceDetails,
    proxy_origin: Option<String>,
    login: Option<Login>,
    session_id: Option<String>,
    sqr_secret: Option<Vec<u8>>,
    auth_token: Option<String>,
    self_key: Option<E2EEKeyData>,
    talk_service: Option<TalkService>,
    sync_state: Option<SyncState>,
    peer_key_cache: HashMap<String, (i32, Vec<u8>)>,
    my_mid: Option<String>,
    display_name_cache: HashMap<String, String>,
    picture_cache: HashMap<String, String>,
    // Email login state (stored between emailLoginStart and emailLoginCheckPin)
    email_login_keynm: Option<String>,
    email_login_encrypted_msg: Option<String>,
    email_login_cert: Option<String>,
    email_login_verifier: Option<String>,
    // E2EE Email Login state
    email_login_e2ee_data: Option<Vec<u8>>,
    email_login_sqr_secret: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl LineClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();
        let device = DeviceDetails::new(DeviceType::IOSIPAD, Some("15.5.0".to_string()));
        Self {
            device,
            proxy_origin: None,
            login: None,
            session_id: None,
            sqr_secret: None,
            auth_token: None,
            self_key: None,
            talk_service: None,
            sync_state: None,
            peer_key_cache: HashMap::new(),
            my_mid: None,
            display_name_cache: HashMap::new(),
            picture_cache: HashMap::new(),
            email_login_keynm: None,
            email_login_encrypted_msg: None,
            email_login_cert: None,
            email_login_verifier: None,
            email_login_e2ee_data: None,
            email_login_sqr_secret: None,
        }
    }

    /// Set device mode (ipad vs desktop)
    #[wasm_bindgen(js_name = "setDevice")]
    pub fn set_device(&mut self, mode: &str) {
        if mode == "desktop" {
            self.device = DeviceDetails::new(DeviceType::DESKTOPWIN, None);
            console_log!("Switched to DESKTOPWIN mode");
        } else {
            self.device = DeviceDetails::new(DeviceType::IOSIPAD, Some("15.5.0".to_string()));
            console_log!("Switched to IOSIPAD mode");
        }
    }

    /// Create a login session and return the QR code URL
    #[wasm_bindgen(js_name = "createQrLogin")]
    pub async fn create_qr_login(&mut self) -> Result<JsValue, JsValue> {
        // Use current origin as proxy endpoint in browser
        let origin = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let request_client = RequestClient::new(self.device.clone(), Some(origin.clone()));
        let login = Login::new(request_client);

        let session_id = login.create_session().await
            .map_err(|e| JsValue::from_str(&format!("create_session: {}", e)))?;
        let callback_url = login.create_qr_code(&session_id).await
            .map_err(|e| JsValue::from_str(&format!("create_qr_code: {}", e)))?;

        let (sqr_secret, e2ee_param) = E2EE::create_sqr_secret();
        let full_url = format!("{}{}", callback_url, e2ee_param);

        self.sqr_secret = Some(sqr_secret.as_bytes().to_vec());
        self.session_id = Some(session_id);
        self.login = Some(login);
        self.proxy_origin = Some(origin);

        console_log!("QR Login URL created");

        let result = serde_json::json!({
            "url": full_url,
            "qrImageUrl": format!(
                "https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={}",
                urlencoding::encode(&full_url)
            )
        });
        Ok(JsValue::from_str(&result.to_string()))
    }

    /// Check if QR code has been scanned (long-poll)
    #[wasm_bindgen(js_name = "checkQrCodeVerified")]
    pub async fn check_qr_code_verified(&self) -> Result<bool, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("Not initialized"))?;
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| JsValue::from_str("No session"))?;

        login.check_qr_code_verified(session_id).await
            .map_err(|e| JsValue::from_str(&format!("check_qr: {}", e)))
    }

    /// Verify certificate (skip PIN if possible)
    #[wasm_bindgen(js_name = "verifyCertificate")]
    pub async fn verify_certificate(&self) -> Result<bool, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("Not initialized"))?;
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| JsValue::from_str("No session"))?;

        match login.verify_certificate(session_id, None).await {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Create PIN code
    #[wasm_bindgen(js_name = "createPinCode")]
    pub async fn create_pin_code(&self) -> Result<String, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("Not initialized"))?;
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| JsValue::from_str("No session"))?;

        login.create_pin_code(session_id).await
            .map_err(|e| JsValue::from_str(&format!("create_pin: {}", e)))
    }

    /// Check if PIN code has been verified (long-poll)
    #[wasm_bindgen(js_name = "checkPinCodeVerified")]
    pub async fn check_pin_code_verified(&self) -> Result<bool, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("Not initialized"))?;
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| JsValue::from_str("No session"))?;

        login.check_pin_code_verified(session_id).await
            .map_err(|e| JsValue::from_str(&format!("check_pin: {}", e)))
    }

    /// Complete QR code login, extract auth token and E2EE keys
    #[wasm_bindgen(js_name = "qrCodeLogin")]
    pub async fn qr_code_login(&mut self) -> Result<String, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("Not initialized"))?;
        let session_id = self.session_id.as_ref()
            .ok_or_else(|| JsValue::from_str("No session"))?;

        let (auth_token, login_val) = login.qr_code_login(session_id).await
            .map_err(|e| JsValue::from_str(&format!("qr_login: {}", e)))?;

        console_log!("Auth token received");

        // Extract E2EE key
        if let Some(sqr_secret_bytes) = &self.sqr_secret {
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(&sqr_secret_bytes[..32]);
            let sqr_secret = x25519_dalek::StaticSecret::from(priv_bytes);
            self.self_key = extract_e2ee_key(&login_val, &sqr_secret);
            if self.self_key.is_some() {
                console_log!("E2EE key extracted successfully");
            }
        }

        // Set up authenticated service client (use proxy origin in browser)
        let mut service_client = RequestClient::new(self.device.clone(), self.proxy_origin.clone());
        service_client.set_auth_token(auth_token.clone());
        self.talk_service = Some(TalkService::new(service_client));
        self.sync_state = Some(SyncState::new());
        self.auth_token = Some(auth_token.clone());

        Ok(auth_token)
    }

    /// Start email/password login. Returns JSON:
    /// - On success: { "authToken": "...", "certificate": "..." }
    /// - On PIN needed: { "pinCode": "..." }
    #[wasm_bindgen(js_name = "emailLoginStart")]
    pub async fn email_login_start(&mut self, email: &str, password: &str) -> Result<JsValue, JsValue> {
        let origin = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let request_client = RequestClient::new(self.device.clone(), Some(origin.clone()));
        let login = Login::new(request_client);

        // Generate client-side PIN (6 digits)
        let mut pin_bytes = [0u8; 4];
        getrandom::getrandom(&mut pin_bytes).map_err(|e| JsValue::from_str(&format!("RNG error: {}", e)))?;
        let pin_val = u32::from_le_bytes(pin_bytes) % 1_000_000;
        let pin_code = format!("{:06}", pin_val);

        // Generate E2EE secret (S0, S0_pub)
        let (secret_key, secret_pk_b64) = E2EE::create_sqr_secret_raw();
        let secret_pk_bytes = general_purpose::STANDARD.decode(&secret_pk_b64)
            .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))?;

        // Encrypt PIN hash
        let pin_hash = E2EE::sha256_sum(&[pin_code.as_bytes()]);
        let e2ee_data = E2EE::encrypt_aes_ecb(&pin_hash, &secret_pk_bytes)
             .map_err(|e| JsValue::from_str(&format!("E2EE encrypt error: {}", e)))?;

        console_log!("Fetching RSA key...");
        let (keynm, nvalue, evalue, session_key) = login.get_rsa_key_info().await
            .map_err(|e| JsValue::from_str(&format!("getRSAKeyInfo: {}", e)))?;
        console_log!("RSA key obtained: {}", keynm);

        let encrypted_msg = Login::rsa_encrypt_credentials(&nvalue, &evalue, &session_key, email, password)
            .map_err(|e| JsValue::from_str(&format!("RSA encrypt: {}", e)))?;

        let device_name = self.device.device_type.as_str();
        console_log!("Calling loginZ (initial)...");
        // pass e2ee_data (loginType=2)
        let result = login.login_z(&keynm, &encrypted_msg, device_name, None, None, Some(&e2ee_data)).await
            .map_err(|e| JsValue::from_str(&format!("loginZ: {}", e)))?;

        // Check if we got an authToken directly
        if let Some(auth_token) = result.get("1").and_then(|v| v.as_str()) {
            console_log!("Email login succeeded directly (certificate present)");
            let cert = result.get("2").and_then(|v| v.as_str()).map(|s| s.to_string());

            // Extract MID from login response field "5" (matching main.rs)
            let mid = result.get("5")
                .or_else(|| result.get("0").and_then(|r| r.get("5")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(ref m) = mid {
                console_log!("MID from email login: {}", m);
                self.my_mid = Some(m.clone());
            }

            // Set up authenticated service client
            self.proxy_origin = Some(origin.clone());
            let mut service_client = RequestClient::new(self.device.clone(), Some(origin));
            service_client.set_auth_token(auth_token.to_string());
            self.talk_service = Some(TalkService::new(service_client));
            self.sync_state = Some(SyncState::new());
            self.auth_token = Some(auth_token.to_string());

            // Fetch profile to populate displayName cache
            if let Some(ts) = self.talk_service.as_ref() {
                if let Ok(profile) = ts.get_profile().await {
                    if let Some(pmid) = profile.get("1").and_then(|v| v.as_str()) {
                        self.my_mid = Some(pmid.to_string());
                        if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                            self.display_name_cache.insert(pmid.to_string(), name.to_string());
                            console_log!("Logged in as: {} ({})", name, pmid);
                        }
                        if let Some(pic) = profile.get("4").and_then(|v| v.as_str()) {
                            self.picture_cache.insert(pmid.to_string(), pic.to_string());
                        }
                    }
                }
            }

            let resp = serde_json::json!({
                "authToken": auth_token,
                "certificate": cert,
            });
            return Ok(JsValue::from_str(&resp.to_string()));
        }

        // No authToken → PIN verification required
        let verifier = result.get("3").and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("No verifier in loginZ response"))?;

        // Display the pincode we generated (matching main.rs)
        console_log!("PIN required: {}", pin_code);

        // Store state for emailLoginCheckPin
        self.login = Some(login);
        self.proxy_origin = Some(origin);
        self.email_login_keynm = Some(keynm);
        self.email_login_encrypted_msg = Some(encrypted_msg);
        self.email_login_verifier = Some(verifier.to_string());
        self.email_login_cert = result.get("2").and_then(|v| v.as_str()).map(|s| s.to_string());
        self.email_login_e2ee_data = Some(e2ee_data);
        
        // Store SQR secret for later E2EE derivation
        self.email_login_sqr_secret = Some(secret_key);

        let resp = serde_json::json!({ "pinCode": pin_code });
        Ok(JsValue::from_str(&resp.to_string()))
    }

    /// Poll for email login PIN verification, then complete login.
    /// Returns JSON: { "authToken": "...", "certificate": "..." }
    #[wasm_bindgen(js_name = "emailLoginCheckPin")]
    pub async fn email_login_check_pin(&mut self) -> Result<JsValue, JsValue> {
        let login = self.login.as_ref()
            .ok_or_else(|| JsValue::from_str("No login in progress"))?;
        let verifier = self.email_login_verifier.as_ref()
            .ok_or_else(|| JsValue::from_str("No verifier"))?;

        console_log!("Polling for E2EE email PIN verification (/LF1)...");
        let e2ee_info = login.poll_email_e2ee_info(verifier).await
            .map_err(|e| JsValue::from_str(&format!("PIN poll/E2EE info: {}", e)))?;

        console_log!("PIN verified, processing E2EE metadata...");

        // Extract metadata
        let metadata = e2ee_info.get("metadata")
             .ok_or_else(|| JsValue::from_str("No metadata in E2EE response"))?;
        let encrypted_key_chain_b64 = metadata.get("encryptedKeyChain").and_then(|v| v.as_str())
             .ok_or_else(|| JsValue::from_str("Missing encryptedKeyChain"))?;
        let public_key_b64 = metadata.get("publicKey").and_then(|v| v.as_str())
             .ok_or_else(|| JsValue::from_str("Missing publicKey"))?;
        let key_id = metadata.get("keyId").and_then(|v| v.as_str())
             .or_else(|| metadata.get("keyId").and_then(|v| v.as_i64()).map(|_| ""))
             .unwrap_or("");
        let e2ee_version = metadata.get("e2eeVersion").and_then(|v| v.as_str()).unwrap_or("1");

        // Restore SQR secret
        let secret_bytes = self.email_login_sqr_secret.as_ref()
            .ok_or_else(|| JsValue::from_str("SQR secret missing"))?;
        let mut sk_bytes = [0u8; 32];
        if secret_bytes.len() == 32 {
            sk_bytes.copy_from_slice(secret_bytes);
        } else {
             return Err(JsValue::from_str("SQR secret invalid length"));
        }
        let sqr_secret = x25519_dalek::StaticSecret::from(sk_bytes);
        
        // Decode E2EE Key
        match E2EE::decode_e2ee_key_v1(
            encrypted_key_chain_b64, public_key_b64, key_id, e2ee_version, secret_bytes
        ) {
            Ok(key_data) => {
                console_log!("E2EE Key extracted: keyId={}", key_data.key_id);
                self.self_key = Some(key_data);
            },
            Err(e) => console_log!("Warning: E2EE key decode failed: {}", e),
        }

        // Encrypt device secret
        let server_pub_bytes = general_purpose::STANDARD.decode(public_key_b64)
            .map_err(|e| JsValue::from_str(&format!("B64 decode failed: {}", e)))?;
        let encrypted_key_chain_bytes = general_purpose::STANDARD.decode(encrypted_key_chain_b64)
            .map_err(|e| JsValue::from_str(&format!("B64 decode failed: {}", e)))?;

        let device_secret = E2EE::encrypt_device_secret(&server_pub_bytes, &sqr_secret.to_bytes(), &encrypted_key_chain_bytes)
            .map_err(|e| JsValue::from_str(&format!("Device secret encrypt failed: {}", e)))?;
        
        // Confirm E2EE login
        let new_verifier = login.confirm_e2ee_login(verifier, &device_secret).await
             .map_err(|e| JsValue::from_str(&format!("confirmE2EELogin: {}", e)))?;

        console_log!("E2EE confirmed, finalizing login...");

        // Re-call loginZ with the new verifier and e2ee_data
        let keynm = self.email_login_keynm.as_ref()
            .ok_or_else(|| JsValue::from_str("No keynm"))?;
        let encrypted_msg = self.email_login_encrypted_msg.as_ref()
            .ok_or_else(|| JsValue::from_str("No encrypted message"))?;
        let device_name = self.device.device_type.as_str();
        let cert = self.email_login_cert.as_deref();
        let e2ee_data = self.email_login_e2ee_data.as_deref();

        let result = login.login_z(keynm, encrypted_msg, device_name, cert, Some(&new_verifier), e2ee_data).await
            .map_err(|e| JsValue::from_str(&format!("loginZ (final): {}", e)))?;

        let auth_token = result.get("1").and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("No authToken after PIN verification"))?;
        let certificate = result.get("2").and_then(|v| v.as_str()).map(|s| s.to_string());

        console_log!("Email login completed successfully");

        // Extract MID from login response field "5" (matching main.rs)
        let mid = result.get("5")
            .or_else(|| result.get("0").and_then(|r| r.get("5")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(ref m) = mid {
            console_log!("MID from email login: {}", m);
            self.my_mid = Some(m.clone());
        }

        // Set up authenticated service client
        let origin = self.proxy_origin.clone();
        let mut service_client = RequestClient::new(self.device.clone(), origin);
        service_client.set_auth_token(auth_token.to_string());
        self.talk_service = Some(TalkService::new(service_client));
        self.sync_state = Some(SyncState::new());
        self.auth_token = Some(auth_token.to_string());

        // Fetch profile to populate displayName cache (matching main.rs)
        if let Some(ts) = self.talk_service.as_ref() {
            if let Ok(profile) = ts.get_profile().await {
                if let Some(pmid) = profile.get("1").and_then(|v| v.as_str()) {
                    self.my_mid = Some(pmid.to_string());
                    if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                        self.display_name_cache.insert(pmid.to_string(), name.to_string());
                        console_log!("Logged in as: {} ({})", name, pmid);
                    }
                    if let Some(pic) = profile.get("4").and_then(|v| v.as_str()) {
                        self.picture_cache.insert(pmid.to_string(), pic.to_string());
                    }
                }
            }
        }

        // Clear email login state
        self.email_login_keynm = None;
        self.email_login_encrypted_msg = None;
        self.email_login_verifier = None;
        self.email_login_cert = None;
        self.email_login_e2ee_data = None;
        self.email_login_sqr_secret = None;

        let resp = serde_json::json!({
            "authToken": auth_token,
            "certificate": certificate,
        });
        Ok(JsValue::from_str(&resp.to_string()))
    }

    /// Export credentials (auth token + E2EE key) as JSON for persistence
    #[wasm_bindgen(js_name = "exportCredentials")]
    pub fn export_credentials(&self) -> JsValue {
        let auth_token = match &self.auth_token {
            Some(t) => t.clone(),
            None => return JsValue::NULL,
        };

        let e2ee_key = self.self_key.as_ref().map(|k| {
            serde_json::json!({
                "keyId": k.key_id,
                "privKey": general_purpose::STANDARD.encode(&k.priv_key),
                "pubKey": general_purpose::STANDARD.encode(&k.pub_key),
                "e2eeVersion": k.e2ee_version,
            })
        });

        // Serialize peer key cache (mid -> {id, b64key})
        let peer_keys: serde_json::Value = self.peer_key_cache.iter().map(|(mid, (key_id, key))| {
            (mid.clone(), serde_json::json!({
                "id": key_id,
                "key": general_purpose::STANDARD.encode(key)
            }))
        }).collect::<serde_json::Map<String, serde_json::Value>>().into();

        // Serialize display name cache
        let display_names: serde_json::Value = self.display_name_cache.iter()
            .map(|(mid, name)| (mid.clone(), serde_json::Value::String(name.clone())))
            .collect::<serde_json::Map<String, serde_json::Value>>().into();

        // Serialize picture path cache
        let pictures: serde_json::Value = self.picture_cache.iter()
            .map(|(mid, path)| (mid.clone(), serde_json::Value::String(path.clone())))
            .collect::<serde_json::Map<String, serde_json::Value>>().into();

        let creds = serde_json::json!({
            "authToken": auth_token,
            "e2eeKey": e2ee_key,
            "peerKeys": peer_keys,
            "myMid": self.my_mid,
            "deviceType": match self.device.device_type {
                DeviceType::DESKTOPWIN => "desktop",
                DeviceType::IOSIPAD => "ipad",
                _ => "ipad",
            },
            "displayNames": display_names,
            "pictures": pictures,
        });

        JsValue::from_str(&creds.to_string())
    }

    /// Restore session from saved credentials JSON (no network call needed)
    #[wasm_bindgen(js_name = "loginWithToken")]
    pub fn login_with_token(&mut self, credentials_json: &str) -> Result<(), JsValue> {
        let creds: serde_json::Value = serde_json::from_str(credentials_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid credentials JSON: {}", e)))?;

        let auth_token = creds.get("authToken")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("Missing authToken"))?
            .to_string();

        // Restore E2EE key if present
        if let Some(e2ee) = creds.get("e2eeKey").filter(|v| !v.is_null()) {
            let key_id = e2ee.get("keyId").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let e2ee_version = e2ee.get("e2eeVersion").and_then(|v| v.as_str()).unwrap_or("1").to_string();

            let priv_key: Vec<u8> = e2ee.get("privKey")
                .and_then(|v| v.as_str())
                .and_then(|s| general_purpose::STANDARD.decode(s).ok())
                .unwrap_or_default();
            let pub_key: Vec<u8> = e2ee.get("pubKey")
                .and_then(|v| v.as_str())
                .and_then(|s| general_purpose::STANDARD.decode(s).ok())
                .unwrap_or_default();

            if !priv_key.is_empty() && !pub_key.is_empty() {
                self.self_key = Some(E2EEKeyData {
                    key_id,
                    priv_key,
                    pub_key,
                    e2ee_version,
                });
                console_log!("E2EE key restored from saved credentials");
            }
        }

        // Set up authenticated service client
        let origin = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .unwrap_or_else(|| "http://localhost:8080".to_string());

        // Restore device type
        if let Some(device_type_str) = creds.get("deviceType").and_then(|v| v.as_str()) {
            if device_type_str == "desktop" {
                 self.device = DeviceDetails::new(DeviceType::DESKTOPWIN, None);
                 console_log!("Restored device type: DESKTOPWIN");
            } else {
                 self.device = DeviceDetails::new(DeviceType::IOSIPAD, Some("15.5.0".to_string()));
                 console_log!("Restored device type: IOSIPAD");
            }
        }

        let mut service_client = RequestClient::new(self.device.clone(), Some(origin.clone()));
        service_client.set_auth_token(auth_token.clone());
        self.talk_service = Some(TalkService::new(service_client));
        self.sync_state = Some(SyncState::new());
        self.auth_token = Some(auth_token);
        self.proxy_origin = Some(origin);

        // Restore peer key cache if present
        if let Some(peer_keys) = creds.get("peerKeys").and_then(|v| v.as_object()) {
            for (mid, key_val) in peer_keys {
                // Support both old format (string) and new format (object)
                if let Some(key_b64) = key_val.as_str() {
                    if let Ok(key_bytes) = general_purpose::STANDARD.decode(key_b64) {
                        // Default ID 0 for legacy format
                        self.peer_key_cache.insert(mid.clone(), (0, key_bytes));
                    }
                } else if let Some(obj) = key_val.as_object() {
                    let key_id = obj.get("id").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                    if let Some(key_b64) = obj.get("key").and_then(|v| v.as_str()) {
                        if let Ok(key_bytes) = general_purpose::STANDARD.decode(key_b64) {
                            self.peer_key_cache.insert(mid.clone(), (key_id, key_bytes));
                        }
                    }
                }
            }
            console_log!("Restored {} peer E2EE public keys", self.peer_key_cache.len());
        }

        // Restore myMid if present
        if let Some(mid) = creds.get("myMid").and_then(|v| v.as_str()) {
            self.my_mid = Some(mid.to_string());
        }

        // Restore display name cache if present
        if let Some(display_names) = creds.get("displayNames").and_then(|v| v.as_object()) {
            for (mid, name_val) in display_names {
                if let Some(name) = name_val.as_str() {
                    self.display_name_cache.insert(mid.clone(), name.to_string());
                }
            }
            console_log!("Restored {} display name mappings", self.display_name_cache.len());
        }

        // Restore picture path cache if present
        if let Some(pictures) = creds.get("pictures").and_then(|v| v.as_object()) {
            for (mid, path_val) in pictures {
                if let Some(path) = path_val.as_str() {
                    self.picture_cache.insert(mid.clone(), path.to_string());
                }
            }
            console_log!("Restored {} picture path mappings", self.picture_cache.len());
        }

        console_log!("Session restored from saved credentials");
        Ok(())
    }

    /// Poll for new messages, returns JSON array of message objects
    #[wasm_bindgen(js_name = "pollMessages")]
    pub async fn poll_messages(&mut self) -> Result<JsValue, JsValue> {
        if self.talk_service.is_none() || self.sync_state.is_none() {
            return Err(JsValue::from_str("Not logged in"));
        }

        // Take sync_state out temporarily to satisfy borrow checker
        let mut sync_state = self.sync_state.take().unwrap();
        let operations = {
            let talk_service = self.talk_service.as_ref().unwrap();
            talk_service.sync(&mut sync_state).await
                .map_err(|e| JsValue::from_str(&format!("sync: {}", e)))
        };
        self.sync_state = Some(sync_state);
        let operations = operations?;

        // Ensure my_mid is populated and own displayName is cached.
        // Also fetch profile when my_mid was restored from credentials but displayName is missing.
        let need_profile = self.talk_service.is_some() && (
            self.my_mid.is_none() ||
            self.my_mid.as_ref().map_or(false, |mid| !self.display_name_cache.contains_key(mid))
        );
        if need_profile {
             let ts = self.talk_service.as_ref().unwrap();
             match ts.get_profile().await {
                  Ok(profile) => {
                       if let Some(mid) = profile.get("1").and_then(|v| v.as_str()) {
                           self.my_mid = Some(mid.to_string());
                           // Cache own displayName from profile field 3
                           if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                               self.display_name_cache.insert(mid.to_string(), name.to_string());
                               console_log!("Logged in as: {}", name);
                           }
                           // Cache own picturePath from profile field 4
                           if let Some(pic) = profile.get("4").and_then(|v| v.as_str()) {
                               self.picture_cache.insert(mid.to_string(), pic.to_string());
                           }
                       }
                  },
                  Err(e) => console_log!("Failed to fetch profile: {}", e)
             }
        }

        let mut messages = Vec::new();

        for op in &operations {
            let op_type = op.get("3").and_then(|v| v.as_i64()).unwrap_or(0);

            if op_type == 25 || op_type == 26 {
                if let Some(msg) = op.get("20") {
                    let from = msg.get("1").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let to = msg.get("2").and_then(|v| v.as_str()).unwrap_or("");
                    let text = decrypt_message(
                        msg, &self.self_key,
                        self.talk_service.as_ref().unwrap(),
                        &mut self.peer_key_cache,
                        &self.my_mid
                    ).await;
                    let is_send = op_type == 25;

                    // Resolve displayName and picturePath for from and to MIDs
                    let from_name = resolve_display_name(
                        from, self.talk_service.as_ref().unwrap(),
                        &mut self.display_name_cache, &mut self.picture_cache
                    ).await;
                    let to_name = resolve_display_name(
                        to, self.talk_service.as_ref().unwrap(),
                        &mut self.display_name_cache, &mut self.picture_cache
                    ).await;
                    let from_pic = self.picture_cache.get(from).cloned().unwrap_or_default();
                    let to_pic = self.picture_cache.get(to).cloned().unwrap_or_default();

                    messages.push(serde_json::json!({
                        "from": from,
                        "to": to,
                        "fromName": from_name,
                        "toName": to_name,
                        "fromPic": from_pic,
                        "toPic": to_pic,
                        "text": text,
                        "isSend": is_send,
                        "timestamp": js_sys::Date::now() as u64
                    }));
                }
            }
        }

        Ok(JsValue::from_str(&serde_json::to_string(&messages)
            .map_err(|e| JsValue::from_str(&format!("json: {}", e)))?))
    }
}

fn extract_e2ee_key(
    login_val: &serde_json::Value,
    sqr_secret: &x25519_dalek::StaticSecret,
) -> Option<E2EEKeyData> {
    let result = login_val.get("0")?;
    let metadata_map = result.get("4")?;

    let get_val = |key: &str| -> Option<&str> {
        if let Some(v) = metadata_map.get(key) { return v.as_str(); }
        if let Some(v) = metadata_map.get(&format!("\"{}\"", key)) { return v.as_str(); }
        if let Some(obj) = metadata_map.as_object() {
            for (k, v) in obj {
                let clean_k = k.trim_matches('"');
                if clean_k == key { return v.as_str(); }
            }
        }
        None
    };

    let encrypted_key_chain = get_val("encryptedKeyChain")?;
    let public_key = get_val("publicKey")?;
    let key_id = get_val("keyId")?;
    let e2ee_version = get_val("e2eeVersion").unwrap_or("1");

    let secret_bytes = sqr_secret.as_bytes();

    match E2EE::decode_e2ee_key_v1(encrypted_key_chain, public_key, key_id, e2ee_version, secret_bytes) {
        Ok(key_data) => {
            console_log!("E2EE Key extracted: keyId={}", key_data.key_id);
            Some(key_data)
        },
        Err(e) => {
            console_log!("E2EE key decode error: {}", e);
            None
        }
    }
}

async fn decrypt_message(
    msg: &serde_json::Value,
    self_key: &Option<E2EEKeyData>,
    talk_service: &TalkService,
    peer_key_cache: &mut HashMap<String, (i32, Vec<u8>)>,
    my_mid: &Option<String>,
) -> String {
    let raw_text = msg.get("10").and_then(|v| v.as_str()).unwrap_or("[No text]");

    if self_key.is_none() {
        return raw_text.to_string();
    }
    let self_key_data = self_key.as_ref().unwrap();

    let has_e2ee = msg.get("18")
        .and_then(|v| v.as_object())
        .map(|obj| obj.contains_key("e2eeVersion") || obj.contains_key("\"e2eeVersion\""))
        .unwrap_or(false);

    if !has_e2ee {
        return raw_text.to_string();
    }

    let from = msg.get("1").and_then(|v| v.as_str()).unwrap_or("");
    let to_msg = msg.get("2").and_then(|v| v.as_str()).unwrap_or("");

    // Determine correct 'to' AAD: if I am receiver, use my MID. If outgoing, use recipient.
    let to = if let Some(me) = my_mid {
        if from == me { to_msg } else { me }
    } else {
        to_msg
    };

    let chunks: Option<Vec<Vec<u8>>> = msg.get("20")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().filter_map(|c| {
                c.as_str().and_then(|s| {
                    base64::engine::general_purpose::STANDARD.decode(s).ok()
                })
            }).collect()
        });

    if let Some(chunks) = chunks {
        if chunks.len() >= 4 {
            let sender_key_id = if chunks.len() > 3 && chunks[3].len() >= 4 {
                i32::from_be_bytes([chunks[3][0], chunks[3][1], chunks[3][2], chunks[3][3]])
            } else { 0 };

            let receiver_key_id = if chunks.len() > 4 && chunks[4].len() >= 4 {
                i32::from_be_bytes([chunks[4][0], chunks[4][1], chunks[4][2], chunks[4][3]])
            } else { 0 };

            let is_self = if let Some(me) = my_mid { from == me } else { false };
            let peer_mid = if is_self { to_msg } else { from };
            let target_key_id = if is_self { receiver_key_id } else { sender_key_id };

            let peer_pub_key = get_peer_public_key(peer_mid, talk_service, peer_key_cache, target_key_id).await;
            
            if let Some(peer_public_key) = peer_pub_key {
                let content_type = msg.get("15").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let spec_version = msg.get("18").and_then(|v| v.as_object())
                    .and_then(|o| o.get("e2eeVersion").or(o.get("\"e2eeVersion\"")))
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(2); // Default to v2 if not specified

                let result = if spec_version == 1 {
                    E2EE::decrypt_e2ee_message_v1(
                        &chunks,
                        &self_key_data.priv_key,
                        &peer_public_key
                    )
                } else {
                    E2EE::decrypt_e2ee_message_v2(
                        to, from, &chunks,
                        &self_key_data.priv_key, &peer_public_key,
                        spec_version, content_type
                    )
                };

                match result {
                    Ok(decrypted_json) => {
                         if let Some(text) = decrypted_json.get("text").and_then(|v| v.as_str()) {
                             return text.to_string();
                         }
                         return format!("[E2EE v{} JSON: {}]", spec_version, decrypted_json);
                    },
                    Err(e) => {
                        let err = format!("[E2EE v{} error: {} (KeyID:{})]", spec_version, e, sender_key_id);
                        console_log!("{}", err);
                        return err;
                    }
                }
            } else {
                 let err = format!("[E2EE error: No public key found for {} (KeyID:{})]", from, sender_key_id);
                 console_log!("{}", err);
                 return err;
            }
        }
    }

    raw_text.to_string()
}

// Resolve a MID to its displayName, with caching.
// MIDs starting with 'c' are chat/group MIDs → use getChats (Chat field 6 = chatName, 7 = picturePath).
// Other MIDs are user MIDs → use getContact (Contact field 22 = displayName, 27 = overridden, 37 = picturePath).
async fn resolve_display_name(
    mid: &str,
    talk_service: &TalkService,
    cache: &mut HashMap<String, String>,
    pic_cache: &mut HashMap<String, String>,
) -> String {
    if mid.is_empty() {
        return String::new();
    }
    if let Some(name) = cache.get(mid) {
        // Only return cached name if we also have the picture (to support incremental avatar loading)
        if pic_cache.contains_key(mid) {
            return name.clone();
        }
        // If missing picture, fall through to fetch contact
    }

    if mid.starts_with('c') {
        // Chat/group MID → use getChats to get chatName
        match talk_service.get_chats(&[mid]).await {
            Ok(resp) => {
                // GetChatsResponse field 1 = chats (list of Chat)
                // Chat field 6 = chatName, field 7 = picturePath
                if let Some(chats) = resp.get("1").and_then(|v| v.as_array()) {
                    if let Some(chat) = chats.first() {
                        let name = chat.get("6")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or(mid)
                            .to_string();
                        if let Some(pic) = chat.get("7").and_then(|v| v.as_str()) {
                            pic_cache.insert(mid.to_string(), pic.to_string());
                        }
                        console_log!("Resolved chatName for {}: {}", mid, name);
                        cache.insert(mid.to_string(), name.clone());
                        return name;
                    }
                }
                cache.insert(mid.to_string(), mid.to_string());
                mid.to_string()
            }
            Err(e) => {
                console_log!("Warning: Failed to resolve chatName for {}: {}", mid, e);
                cache.insert(mid.to_string(), mid.to_string());
                mid.to_string()
            }
        }
    } else {
        // User MID → use getContact
        match talk_service.get_contact(mid).await {
            Ok(contact) => {
                // Prefer displayNameOverridden (field 27) if set, otherwise displayName (field 22)
                let name = contact.get("27")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .or_else(|| contact.get("22").and_then(|v| v.as_str()))
                    .unwrap_or(mid)
                    .to_string();
                // Contact field 37 = picturePath
                if let Some(pic) = contact.get("37").and_then(|v| v.as_str()) {
                    pic_cache.insert(mid.to_string(), pic.to_string());
                }
                console_log!("Resolved displayName for {}: {}", mid, name);
                cache.insert(mid.to_string(), name.clone());
                name
            }
            Err(e) => {
                console_log!("Warning: Failed to resolve displayName for {}: {}", mid, e);
                cache.insert(mid.to_string(), mid.to_string());
                mid.to_string()
            }
        }
    }
}

async fn get_peer_public_key(
    mid: &str,
    talk_service: &TalkService,
    cache: &mut HashMap<String, (i32, Vec<u8>)>,
    expected_key_id: i32,
) -> Option<Vec<u8>> {
    // Check cache first
    if let Some((cached_id, key)) = cache.get(mid) {
        // If ID matches or we don't know the expected ID (0), use cached
        if *cached_id == expected_key_id || expected_key_id == 0 {
            return Some(key.clone());
        }
        console_log!("Cached E2EE key mismatch for {}: has {}, need {}. Renegotiating...", mid, cached_id, expected_key_id);
    }

    // Negotiate/Fetch new key
    match talk_service.negotiate_e2ee_public_key(mid).await {
        Ok((key_id, key_data)) => {
            let key_id_i32 = key_id as i32;
            console_log!("Negotiated E2EE public key for {}: ID {}", mid, key_id);
            // Update cache regardless of match (it's the latest available)
            cache.insert(mid.to_string(), (key_id_i32, key_data.clone()));
            
            if key_id_i32 != expected_key_id && expected_key_id != 0 {
                console_log!("Warning: Negotiated key ID {} does not match expected {}", key_id, expected_key_id);
            }
            Some(key_data)
        }
        Err(e) => {
            console_log!("Failed to get E2EE public key for {}: {}", mid, e);
            None
        }
    }
}
