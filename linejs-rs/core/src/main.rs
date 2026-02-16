use linejs_core::device::{DeviceDetails, DeviceType};
use linejs_core::request::RequestClient;
use linejs_core::login::Login;
use linejs_core::service::{TalkService, SyncState};
use linejs_core::e2ee::{E2EE, E2EEKeyData};
use linejs_core::storage::{Credential, SavedE2EEKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use tokio::time::sleep;
use base64::Engine as _;

const CREDENTIAL_PATH: &str = "linejs_credential.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- LINEJS Rust iPad Login & Message Demo ---");

    let device = DeviceDetails::new(DeviceType::IOSIPAD, Some("15.5.0".to_string()));

    // Load saved credentials
    let mut credential = Credential::load(CREDENTIAL_PATH);
    println!("Credential file: {}", CREDENTIAL_PATH);
    if credential.has_auth_token() {
        println!("Found saved auth token, attempting token login...");
    }
    if credential.has_qr_cert() {
        println!("Found saved QR certificate (PIN-less re-login available)");
    }

    // Attempt token-based login if we have a saved auth token
    let (auth_token, self_key) = if credential.has_auth_token() {
        match try_token_login(&device, &credential).await {
            Ok((token, key)) => {
                println!("Token login successful!");
                (token, key)
            }
            Err(e) => {
                println!("Token login failed ({}), falling back to QR login...", e);
                do_qr_login(&device, &mut credential).await?
            }
        }
    } else {
        println!("No saved credentials, starting QR login...");
        do_qr_login(&device, &mut credential).await?
    };

    // Set up authenticated service client for message polling
    let mut service_client = RequestClient::new(device, None);
    service_client.set_auth_token(auth_token);
    let talk_service = TalkService::new(service_client);
    let mut sync_state = SyncState::new();

    // Cache peer public keys to avoid repeated negotiation calls
    let mut peer_key_cache: HashMap<String, Vec<u8>> = HashMap::new();
    let my_mid = credential.mid.clone().unwrap_or_default();

    println!("\nListening for messages... (Press Ctrl+C to stop)");

    // Poll for incoming messages via TalkService sync
    loop {
        match talk_service.sync(&mut sync_state).await {
            Ok(operations) => {
                for op in &operations {
                    // op field 3 = opType (i32): 25=RECEIVE_MESSAGE, 26=SEND_MESSAGE
                    let op_type = op.get("3").and_then(|v| v.as_i64()).unwrap_or(0);

                    if op_type == 25 || op_type == 26 {
                        // op field 20 = message struct
                        if let Some(msg) = op.get("20") {
                            let text = decrypt_message_text(
                                msg, &self_key, &talk_service, &mut peer_key_cache, &my_mid
                            ).await;
                            let from = msg.get("1").and_then(|v| v.as_str()).unwrap_or("Unknown");
                            let epoch_secs = SystemTime::now()
                                .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

                            println!("[{}] [{}]: {}", epoch_secs, from, text);
                        }
                    }
                }
            },
            Err(e) => {
                println!("Sync error: {}", e);
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Try to login using a saved auth token by setting it and testing with a sync call.
async fn try_token_login(
    device: &DeviceDetails,
    credential: &Credential,
) -> Result<(String, Option<E2EEKeyData>), Box<dyn std::error::Error>> {
    let token = credential.auth_token.as_ref().unwrap().clone();

    // Set up service client with saved token and validate via sync
    let mut test_client = RequestClient::new(device.clone(), None);
    test_client.set_auth_token(token.clone());
    let talk_service = TalkService::new(test_client);
    let mut test_state = SyncState::new();

    // If sync succeeds, the token is still valid
    talk_service.sync(&mut test_state).await
        .map_err(|e| format!("Token validation failed: {}", e))?;

    println!("Auth Token: {}...{}", &token[..8.min(token.len())], &token[token.len().saturating_sub(4)..]);

    // Restore saved E2EE key
    let self_key = credential.get_e2ee_key();
    if let Some(ref key) = self_key {
        println!("Restored E2EE key from credentials: keyId={}", key.key_id);
    } else {
        println!("Warning: No saved E2EE key, messages will not be decrypted");
    }

    Ok((token, self_key))
}

/// Perform full QR code login flow, using saved qr_cert if available to skip PIN.
/// Saves credentials (auth_token, qr_cert, mid, e2ee_key) after successful login.
async fn do_qr_login(
    device: &DeviceDetails,
    credential: &mut Credential,
) -> Result<(String, Option<E2EEKeyData>), Box<dyn std::error::Error>> {
    let request_client = RequestClient::new(device.clone(), None);
    let login = Login::new(request_client);

    println!("Connecting to LINE services...");
    let session_id = login.create_session().await?;
    let callback_url = login.create_qr_code(&session_id).await?;

    // Generate E2EE secret and append to QR URL
    let (sqr_secret, e2ee_param) = E2EE::create_sqr_secret();
    let full_url = format!("{}{}", callback_url, e2ee_param);

    let sep = "=".repeat(40);
    println!("\n{}", sep);
    println!("LOGIN QR CODE GENERATED");
    println!("{}", sep);
    println!("\nScan this URL in your LINE app:");
    println!("{}", full_url);
    println!("\nAlternatively, open this link to see the QR code:");
    println!("https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={}", urlencoding::encode(&full_url));
    println!("\n{}", sep);

    // Long-poll for QR scan (each call blocks up to 180s)
    loop {
        println!("Waiting for QR code scan...");
        match login.check_qr_code_verified(&session_id).await {
            Ok(true) => {
                println!("QR Code Scanned!");
                break;
            }
            Ok(false) => {
                println!("Long-poll timed out, retrying...");
                continue;
            }
            Err(e) => {
                return Err(format!("QR verification error: {}", e).into());
            }
        }
    }

    // Try verifyCertificate with saved qr_cert first (skip PIN if cert is valid)
    let saved_cert = credential.qr_cert.as_deref();
    let need_pincode = match login.verify_certificate(&session_id, saved_cert).await {
        Ok(()) => {
            println!("Certificate verified, skipping PIN code.");
            false
        }
        Err(_) => true,
    };

    if need_pincode {
        let pincode = login.create_pin_code(&session_id).await?;
        println!("\n{}", sep);
        println!("PINCODE: {}", pincode);
        println!("Enter this code on your mobile device.");
        println!("{}\n", sep);

        // Long-poll for pincode authorization (each call blocks up to 180s)
        loop {
            println!("Waiting for PIN code verification...");
            match login.check_pin_code_verified(&session_id).await {
                Ok(true) => {
                    println!("Pincode Authorized!");
                    break;
                }
                Ok(false) => {
                    println!("Long-poll timed out, retrying...");
                    continue;
                }
                Err(e) => {
                    return Err(format!("PIN verification error: {}", e).into());
                }
            }
        }
    }

    // Login and extract auth token + E2EE key metadata
    let (auth_token, login_val) = login.qr_code_login(&session_id).await?;
    println!("Successfully logged in!");
    println!("Auth Token: {}", auth_token);

    // Extract QR certificate (PEM) from login response field "0"."1"
    // TypeScript: const { 1: pem, 2: authToken, 4: e2eeInfo, 5: _mid } = response;
    let qr_cert = login_val.get("0")
        .and_then(|r| r.get("1"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract MID from login response field "0"."5"
    let mid = login_val.get("0")
        .and_then(|r| r.get("5"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract E2EE key data from login response
    let self_key = extract_e2ee_key(&login_val, &sqr_secret);
    if let Some(ref key) = self_key {
        println!("E2EE Key extracted: keyId={}", key.key_id);
    } else {
        println!("Warning: E2EE key not found in login response, messages will not be decrypted");
    }

    // Save all credentials to file
    credential.auth_token = Some(auth_token.clone());
    if let Some(ref cert) = qr_cert {
        println!("Saving QR certificate for next login (PIN-less re-auth)");
        credential.qr_cert = Some(cert.clone());
    }
    credential.mid = mid.clone();
    if let Some(ref key) = self_key {
        credential.e2ee_key = Some(SavedE2EEKey::from_key_data(key));
    }
    match credential.save(CREDENTIAL_PATH) {
        Ok(()) => println!("Credentials saved to {}", CREDENTIAL_PATH),
        Err(e) => println!("Warning: Failed to save credentials: {}", e),
    }

    Ok((auth_token, self_key))
}

// Extract E2EE self-key from the qrCodeLogin response using the SQR secret.
// The login response contentMetadata is likely in field "4" (based on debug output).
fn extract_e2ee_key(
    login_val: &serde_json::Value,
    sqr_secret: &x25519_dalek::StaticSecret,
) -> Option<E2EEKeyData> {
    // Navigate: result field "0" = struct
    let result = login_val.get("0")?;
    
    // Debug: Try to find contentMetadata map. JSON dump shows it's likely field "4".
    // Field 4 keys seem to be quoted in debug output? e.g. "\"keyId\""
    let metadata_map = result.get("4")?;

    // Helper to get value from map with or without quotes
    let get_val = |key: &str| -> Option<&str> {
        if let Some(v) = metadata_map.get(key) { return v.as_str(); }
        if let Some(v) = metadata_map.get(&format!("\"{}\"" , key)) { return v.as_str(); }
        // Also try stripping quotes if map keys are quoted but we query clean key
        // Iterate over keys to find match? (Slow but safe for small map)
        if let Some(obj) = metadata_map.as_object() {
             for (k, v) in obj {
                 let clean_k = k.trim_matches('"');
                 if clean_k == key {
                     return v.as_str();
                 }
             }
        }
        None
    };

    // metadata_map is parsed as a JSON object with string keys and string values
    let encrypted_key_chain = get_val("encryptedKeyChain")?;
    let public_key = get_val("publicKey")?;
    let key_id = get_val("keyId")?;
    let e2ee_version = get_val("e2eeVersion").unwrap_or("1");

    println!("E2EE Metadata found:");
    println!("  KeyId: {}", key_id);
    println!("  PublicKey len: {}", public_key.len());
    println!("  EncryptedKeyChain len: {}", encrypted_key_chain.len());

    // Extract raw secret bytes from StaticSecret for key chain decryption
    let secret_bytes = sqr_secret.as_bytes();

    match E2EE::decode_e2ee_key_v1(
        encrypted_key_chain, public_key, key_id, e2ee_version, secret_bytes,
    ) {
        Ok(key_data) => {
            println!("E2EE Key extracted successfully: keyId={}", key_data.key_id);
            Some(key_data)
        },
        Err(e) => {
            println!("E2EE key decode error: {}", e);
            None
        }
    }
}

// Decrypt E2EE message text, falling back to plain text field if decryption fails.
async fn decrypt_message_text(
    msg: &serde_json::Value,
    self_key: &Option<E2EEKeyData>,
    talk_service: &TalkService,
    peer_key_cache: &mut HashMap<String, Vec<u8>>,
    my_mid: &str,
) -> String {
    // Field 10 is plain text fallback
    let raw_text = msg.get("10").and_then(|v| v.as_str()).unwrap_or("[No text]");

    // Check if we have self key
    if self_key.is_none() {
        return raw_text.to_string();
    }
    let self_key_data = self_key.as_ref().unwrap();

    // Check contentMetadata (field 18) for e2eeVersion
    if let Some(meta_val) = msg.get("18") {
        let has_e2ee = if let Some(obj) = meta_val.as_object() {
             obj.contains_key("e2eeVersion")
        } else { false };

        if has_e2ee {
            // Read e2eeVersion from contentMetadata
            let e2ee_version = meta_val.as_object()
                .and_then(|obj| obj.get("e2eeVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or("2");

            // Extract from (field 1) and to (field 2)
            let from = msg.get("1").and_then(|v| v.as_str()).unwrap_or("");
            let to = msg.get("2").and_then(|v| v.as_str()).unwrap_or("");
            let is_self = from == my_mid;

            println!("DEBUG: E2EE v{} msg from={} to={} isSelf={}", e2ee_version, from, to, is_self);

            // Extract chunks (field 20) - Thrift binary list.
            // Thrift reader stores valid-UTF-8 binary as plain strings, non-UTF-8 as base64.
            // Try base64 decode first; fall back to raw string bytes.
            let chunks: Option<Vec<Vec<u8>>> = msg.get("20")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().filter_map(|c| {
                        c.as_str().map(|s| {
                            base64::engine::general_purpose::STANDARD.decode(s)
                                .unwrap_or_else(|_| s.as_bytes().to_vec())
                        })
                    }).collect()
                });

            if let Some(chunks) = chunks {
                println!("DEBUG: Chunks: count={}, sizes={:?}",
                    chunks.len(),
                    chunks.iter().map(|c| c.len()).collect::<Vec<_>>());

                let min_chunks = if e2ee_version == "2" { 4 } else { 3 };
                if chunks.len() >= min_chunks {
                    // Determine peer MID: for self-sent use recipient, for received use sender
                    let peer_mid = if is_self { to } else { from };
                    let peer_pub_key = get_peer_public_key(peer_mid, talk_service, peer_key_cache).await;
                    if peer_pub_key.is_none() {
                        return "[E2EE: Peer key not found]".to_string();
                    }
                    let peer_public_key = peer_pub_key.unwrap();

                    println!("DEBUG: selfPrivKey[..4]={:02x?} peerPubKey[..4]={:02x?}",
                        &self_key_data.priv_key[..4.min(self_key_data.priv_key.len())],
                        &peer_public_key[..4.min(peer_public_key.len())]);

                    // Dispatch to V1 or V2 decryption
                    let decrypt_result = if e2ee_version == "2" {
                        let content_type = msg.get("15").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                        E2EE::decrypt_e2ee_message_v2(
                            to, from, &chunks,
                            &self_key_data.priv_key, &peer_public_key,
                            2, content_type
                        )
                    } else {
                        E2EE::decrypt_e2ee_message_v1(
                            &chunks,
                            &self_key_data.priv_key, &peer_public_key,
                        )
                    };

                    match decrypt_result {
                        Ok(decrypted_json) => {
                            println!("DEBUG: Decrypted OK: {}", decrypted_json);
                            if let Some(text) = decrypted_json.get("text").and_then(|v| v.as_str()) {
                                return text.to_string();
                            }
                            return format!("[E2EE JSON: {}]", decrypted_json);
                        },
                        Err(e) => {
                            println!("DEBUG: E2EE decrypt failed: {}", e);
                            return format!("[E2EE decrypt error: {}]", e);
                        }
                    }
                } else {
                    println!("DEBUG: Not enough chunks (need >={}, got {})", min_chunks, chunks.len());
                }
            } else {
                println!("DEBUG: No chunks in field 20");
            }
        }
    }

    raw_text.to_string()
}

// Get peer's E2EE public key, using cache or calling negotiateE2EEPublicKey
async fn get_peer_public_key(
    mid: &str,
    talk_service: &TalkService,
    cache: &mut HashMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    if let Some(key) = cache.get(mid) {
        return Some(key.clone());
    }

    match talk_service.negotiate_e2ee_public_key(mid).await {
        Ok((_key_id, key_data)) => {
            cache.insert(mid.to_string(), key_data.clone());
            Some(key_data)
        }
        Err(e) => {
            println!("Failed to get E2EE public key for {}: {}", mid, e);
            None
        }
    }
}
