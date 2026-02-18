use linejs_core::device::{DeviceDetails, DeviceType};
use linejs_core::request::RequestClient;
use linejs_core::login::Login;
use linejs_core::service::{TalkService, SyncState};
use linejs_core::e2ee::{E2EE, E2EEKeyData};
use linejs_core::storage::{Credential, SavedE2EEKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::io::{Write, stdin};
use tokio::time::sleep;
use base64::Engine as _;

const CREDENTIAL_PATH: &str = "line_credential.json";

fn get_credential_path() -> String {
    if std::path::Path::new(CREDENTIAL_PATH).exists() {
        CREDENTIAL_PATH.to_string()
    } else {
        // Try parent directory
        let path = format!("../{}", CREDENTIAL_PATH);
        if std::path::Path::new(&path).exists() {
            path
        } else {
            CREDENTIAL_PATH.to_string()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse device mode from CLI args: `cargo run -- desktop` or `cargo run -- ipad` (default)
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("ipad");
    let device = match mode {
        "desktop" | "pc" => {
            println!("--- LINEJS Rust PC (Windows) Login & Message Demo ---");
            DeviceDetails::new(DeviceType::DESKTOPWIN, None)
        }
        _ => {
            println!("--- LINEJS Rust iPad Login & Message Demo ---");
            DeviceDetails::new(DeviceType::IOSIPAD, Some("15.5.0".to_string()))
        }
    };
    println!("Device mode: {} (usage: {} [ipad|desktop])", mode, args[0]);

    // Load saved credentials
    let credential_path = get_credential_path();
    let mut credential = Credential::load(&credential_path);
    println!("Credential file: {}", credential_path);

    // Attempt token-based login if we have a saved auth token
    let (auth_token, self_key) = if credential.has_auth_token() {
        println!("Found saved auth token, attempting token login...");
        match try_token_login(&device, &mut credential, &credential_path).await {
            Ok((token, key)) => {
                println!("Token login successful!");
                (token, key)
            }
            Err(e) => {
                println!("Token login failed ({}), starting manual login...", e);
                select_login_method(&device, &mut credential, &credential_path).await?
            }
        }
    } else {
        println!("No saved credentials, starting manual login...");
        select_login_method(&device, &mut credential, &credential_path).await?
    };

    // Set up authenticated service client for message polling
    let mut service_client = RequestClient::new(device, None);
    service_client.set_auth_token(auth_token);
    let talk_service = TalkService::new(service_client);
    let mut sync_state = SyncState::new();

    // Cache peer public keys to avoid repeated negotiation calls
    let mut peer_key_cache: HashMap<String, (i64, Vec<u8>)> = HashMap::new();
    let my_mid = credential.mid.clone().unwrap_or_default();

    // Cache MID -> displayName; restore from saved credentials
    let mut display_name_cache: HashMap<String, String> = credential.display_names.clone();
    if !display_name_cache.is_empty() {
        println!("Restored {} display name mappings from credentials", display_name_cache.len());
    }

    // Fetch own display name via getProfile if not already cached
    if !my_mid.is_empty() && !display_name_cache.contains_key(&my_mid) {
        match talk_service.get_profile().await {
            Ok(profile) => {
                if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                    println!("Logged in as: {}", name);
                    display_name_cache.insert(my_mid.clone(), name.to_string());
                }
            }
            Err(e) => println!("Warning: Failed to fetch own profile: {}", e),
        }
    } else if let Some(name) = display_name_cache.get(&my_mid) {
        println!("Logged in as: {}", name);
    }

    println!("\nListening for messages... (Press Ctrl+C to stop)");

    // Poll for incoming messages via TalkService sync
    let mut poll_count: u32 = 0;
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
                            let to = msg.get("2").and_then(|v| v.as_str()).unwrap_or("");
                            let epoch_secs = SystemTime::now()
                                .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

                            // Resolve displayName for from and to MIDs
                            let from_name = resolve_display_name(from, &talk_service, &mut display_name_cache).await;
                            let to_name = resolve_display_name(to, &talk_service, &mut display_name_cache).await;

                            println!("[{}] [{}->{}]: {}", epoch_secs, from_name, to_name, text);
                        }
                    }
                }

                // Periodically save display name cache to credentials
                poll_count += 1;
                if poll_count % 10 == 0 {
                    credential.display_names = display_name_cache.clone();
                    if let Err(e) = credential.save(&credential_path) {
                        println!("Warning: Failed to save credentials: {}", e);
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

async fn select_login_method(
    device: &DeviceDetails,
    credential: &mut Credential,
    credential_path: &str,
) -> Result<(String, Option<E2EEKeyData>), Box<dyn std::error::Error>> {
    println!("\nSelect Login Method:");
    println!("1. Email and Password");
    println!("2. QR Code");
    print!("Choose method [1]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;
    let choice = input.trim();

    if choice == "2" {
        do_qr_login(device, credential, credential_path).await
    } else {
        do_email_login(device, credential, credential_path).await
    }
}

async fn do_email_login(
    device: &DeviceDetails,
    credential: &mut Credential,
    credential_path: &str,
) -> Result<(String, Option<E2EEKeyData>), Box<dyn std::error::Error>> {
    let request_client = RequestClient::new(device.clone(), None);
    let login = Login::new(request_client);

    print!("Enter LINE Email: ");
    std::io::stdout().flush()?;
    let mut email = String::new();
    stdin().read_line(&mut email)?;
    let email = email.trim();

    let password = rpassword::prompt_password("Enter LINE Password: ")?;

    // Client-chosen random 6-digit PIN code for this login session
    let constant_pincode = format!("{:06}", rand::random::<u32>() % 1_000_000);

    // Generate E2EE secret for email login (matching TS createSqrSecret(true))
    let (secret_key, secret_pk_b64) = E2EE::create_sqr_secret_raw();
    let secret_pk_bytes = base64::engine::general_purpose::STANDARD.decode(&secret_pk_b64)?;

    // e2eeData = AES-256-ECB(SHA256(pincode), publicKeyBytes)
    // matching TS: encryptAESECB(getSHA256Sum(constantPincode), Buffer.from(secretPK, "base64"))
    let pin_hash = E2EE::sha256_sum(&[constant_pincode.as_bytes()]);
    let e2ee_data = E2EE::encrypt_aes_ecb(&pin_hash, &secret_pk_bytes)
        .map_err(|e| format!("E2EE data encryption failed: {}", e))?;

    println!("Connecting to LINE services...");
    let (keynm, nvalue, evalue, session_key) = login.get_rsa_key_info().await?;
    let encrypted_msg = Login::rsa_encrypt_credentials(&nvalue, &evalue, &session_key, email, &password)?;

    // First loginZ with loginType=2 (E2EE, e2eeData in field 10)
    let mut result = login.login_z(
        &keynm, &encrypted_msg, device.device_type.as_str(),
        None, None, Some(&e2ee_data),
    ).await?;

    let mut self_key: Option<E2EEKeyData> = None;

    // PIN verification required?
    if result.get("1").and_then(|v| v.as_str()).is_none() {
        let verifier = result.get("3").and_then(|v| v.as_str())
            .ok_or("No verifier found in login response")?;

        // Display the CLIENT-CHOSEN pincode (not server-generated)
        // Matching TS: this.client.emit("pincall", response.pinCode || constantPincode)
        let display_pin = result.get("4")
            .and_then(|v| v.as_str())
            .unwrap_or(&constant_pincode);

        let sep = "=".repeat(40);
        println!("\n{}", sep);
        println!("PINCODE: {}", display_pin);
        println!("Please enter this code on your smartphone LINE app.");
        println!("{}\n", sep);

        // E2EE path: poll /LF1 for E2EE metadata (matching TS requestEmailLogin with enableE2EE=true)
        println!("Waiting for PIN verification (polling /LF1)...");
        let e2ee_info = login.poll_email_e2ee_info(verifier).await?;

        // Extract E2EE metadata from response
        let metadata = e2ee_info.get("metadata")
            .ok_or("No metadata in E2EE info response")?;

        let encrypted_key_chain_b64 = metadata.get("encryptedKeyChain")
            .and_then(|v| v.as_str())
            .ok_or("No encryptedKeyChain in E2EE metadata")?;
        let public_key_b64 = metadata.get("publicKey")
            .and_then(|v| v.as_str())
            .ok_or("No publicKey in E2EE metadata")?;
        let key_id = metadata.get("keyId")
            .and_then(|v| v.as_str())
            .or_else(|| metadata.get("keyId").and_then(|v| v.as_i64()).map(|_| ""))
            .unwrap_or("");
        let e2ee_version = metadata.get("e2eeVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("1");

        println!("E2EE Metadata received: keyId={}, publicKey len={}, encryptedKeyChain len={}",
            key_id, public_key_b64.len(), encrypted_key_chain_b64.len());

        // Decode E2EE key from metadata (matching TS decodeE2EEKeyV1)
        match E2EE::decode_e2ee_key_v1(
            encrypted_key_chain_b64, public_key_b64, key_id, e2ee_version, &secret_key,
        ) {
            Ok(key_data) => {
                println!("E2EE Key extracted: keyId={}", key_data.key_id);
                self_key = Some(key_data);
            }
            Err(e) => println!("Warning: E2EE key decode failed: {}", e),
        }

        // Encrypt device secret (matching TS encryptDeviceSecret)
        let server_pub_bytes = base64::engine::general_purpose::STANDARD.decode(public_key_b64)?;
        let encrypted_key_chain_bytes = base64::engine::general_purpose::STANDARD.decode(encrypted_key_chain_b64)?;
        let device_secret = E2EE::encrypt_device_secret(&server_pub_bytes, &secret_key, &encrypted_key_chain_bytes)
            .map_err(|e| format!("Device secret encryption failed: {}", e))?;

        // confirmE2EELogin → get new verifier
        let new_verifier = login.confirm_e2ee_login(verifier, &device_secret).await?;
        println!("E2EE login confirmed, completing authentication...");

        let cert = result.get("2").and_then(|v| v.as_str());

        // Final loginZ with verifier (loginType=1) + e2eeData
        result = login.login_z(
            &keynm, &encrypted_msg, device.device_type.as_str(),
            cert, Some(&new_verifier), Some(&e2ee_data),
        ).await?;
    }

    let auth_token = result.get("1").and_then(|v| v.as_str())
        .ok_or("Auth token not found after login")?.to_string();

    println!("Successfully logged in!");

    // Extract MID from login response field "5"
    let mid = result.get("5")
        .or_else(|| result.get("0").and_then(|r| r.get("5")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(ref my_mid) = mid {
        let mut temp_client = RequestClient::new(device.clone(), None);
        temp_client.set_auth_token(auth_token.clone());
        let talk_service = TalkService::new(temp_client);
        if let Ok(profile) = talk_service.get_profile().await {
            if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                println!("Logged in as: {} ({})", name, my_mid);
                credential.display_names.insert(my_mid.clone(), name.to_string());
            }
        }
    }

    // Save credentials
    credential.auth_token = Some(auth_token.clone());
    credential.mid = mid;
    if let Some(ref key) = self_key {
        credential.e2ee_key = Some(SavedE2EEKey::from_key_data(key));
        println!("E2EE key saved: keyId={}", key.key_id);
    }

    match credential.save(credential_path) {
        Ok(()) => println!("Credentials saved to {}", credential_path),
        Err(e) => println!("Warning: Failed to save credentials: {}", e),
    }

    Ok((auth_token, self_key))
}

/// Try to login using a saved auth token by setting it and testing with a sync call.
/// Also ensures MID is populated and E2EE key is current.
async fn try_token_login(
    device: &DeviceDetails,
    credential: &mut Credential,
    credential_path: &str,
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

    // Fetch MID from profile if not saved (needed for is_self detection in E2EE)
    if credential.mid.is_none() {
        match talk_service.get_profile().await {
            Ok(profile) => {
                if let Some(mid) = profile.get("1").and_then(|v| v.as_str()) {
                    println!("Fetched MID from profile: {}", mid);
                    credential.mid = Some(mid.to_string());
                    if let Some(name) = profile.get("3").and_then(|v| v.as_str()) {
                        credential.display_names.insert(mid.to_string(), name.to_string());
                    }
                }
            }
            Err(e) => println!("Warning: Failed to fetch profile for MID: {}", e),
        }
    }

    // Restore saved E2EE key and verify it matches server's current key
    let self_key = credential.get_e2ee_key();
    if let Some(ref key) = self_key {
        println!("Restored E2EE key from credentials: keyId={}", key.key_id);
        // Verify key consistency: compute pubKey from privKey and compare with stored pubKey
        if key.priv_key.len() == 32 {
            let derived_pub = x25519_dalek::PublicKey::from(
                &x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(&key.priv_key[..]).unwrap())
            );
            let stored_pub_hex = hex::encode(&key.pub_key);
            let derived_pub_hex = hex::encode(derived_pub.as_bytes());
            if stored_pub_hex != derived_pub_hex {
                println!("WARNING: E2EE key inconsistency! stored pubKey != derived from privKey");
                println!("  stored:  {}", stored_pub_hex);
                println!("  derived: {}", derived_pub_hex);
            } else {
                println!("E2EE key self-check OK: pubKey matches privKey");
            }
        }
        // Also compare with server's registered key for our MID
        if let Some(ref my_mid) = credential.mid {
            match talk_service.negotiate_e2ee_public_key(my_mid).await {
                Ok((server_key_id, server_pub_key)) => {
                    println!("Server has keyId={} for our MID, pubKey[..4]={:02x?}",
                        server_key_id, &server_pub_key[..4.min(server_pub_key.len())]);
                    if server_key_id != key.key_id.parse::<i64>().unwrap_or(0) {
                        println!("WARNING: Server keyId {} != our keyId {}!", server_key_id, key.key_id);
                    }
                    if server_pub_key != key.pub_key {
                        println!("WARNING: Server pubKey != our stored pubKey!");
                        println!("  server: {}", hex::encode(&server_pub_key));
                        println!("  ours:   {}", hex::encode(&key.pub_key));
                    }
                }
                Err(e) => println!("Warning: Failed to check own E2EE key on server: {}", e),
            }
        }
    }

    // Check server's registered E2EE public keys to verify our key is current
    match talk_service.get_e2ee_public_keys().await {
        Ok(server_keys) => {
            println!("Server E2EE keys: {:?}", server_keys.iter().map(|(id, _)| id).collect::<Vec<_>>());
            if let Some(ref key) = self_key {
                let our_key_id: i64 = key.key_id.parse().unwrap_or(0);
                if !server_keys.iter().any(|(id, _)| *id == our_key_id) {
                    println!("WARNING: Saved E2EE keyId={} not found in server keys! E2EE decryption may fail.", key.key_id);
                    println!("  You may need to re-login (email or QR) to register a new E2EE key.");
                }
            } else if !server_keys.is_empty() {
                println!("Warning: No saved E2EE key, but server has {} keys. Re-login needed for E2EE.", server_keys.len());
            }
        }
        Err(e) => println!("Warning: Failed to check E2EE public keys: {}", e),
    }

    if self_key.is_none() {
        println!("Warning: No saved E2EE key, messages will not be decrypted");
    }

    // Save updated credentials (MID may have been fetched)
    let _ = credential.save(credential_path);

    Ok((token, self_key))
}

/// Perform full QR code login flow, using saved qr_cert if available to skip PIN.
/// Saves credentials (auth_token, qr_cert, mid, e2ee_key) after successful login.
async fn do_qr_login(
    device: &DeviceDetails,
    credential: &mut Credential,
    credential_path: &str,
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
    match credential.save(credential_path) {
        Ok(()) => println!("Credentials saved to {}", credential_path),
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
    peer_key_cache: &mut HashMap<String, (i64, Vec<u8>)>,
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
                    let peer_info = get_peer_public_key(peer_mid, talk_service, peer_key_cache).await;
                    if peer_info.is_none() {
                        return "[E2EE: Peer key not found]".to_string();
                    }
                    let (peer_key_id, peer_public_key) = peer_info.unwrap();

                    // Verify keyIds match what the message expects
                    let sender_key_id = if chunks.len() > 3 { i32::from_be_bytes([chunks[3][0], chunks[3][1], chunks[3][2], chunks[3][3]]) as i64 } else { 0 };
                    let receiver_key_id = if chunks.len() > 4 { i32::from_be_bytes([chunks[4][0], chunks[4][1], chunks[4][2], chunks[4][3]]) as i64 } else { 0 };
                    let self_key_id: i64 = self_key_data.key_id.parse().unwrap_or(0);
                    let expected_peer_key_id = if is_self { receiver_key_id } else { sender_key_id };

                    println!("DEBUG: selfKeyId={} peerNegotiatedKeyId={} expectedPeerKeyId={} (is_self={})",
                        self_key_id, peer_key_id, expected_peer_key_id, is_self);
                    if peer_key_id != expected_peer_key_id {
                        println!("WARNING: Peer keyId mismatch! negotiate returned {} but message expects {}", peer_key_id, expected_peer_key_id);
                    }
                    let expected_self_key_id = if is_self { sender_key_id } else { receiver_key_id };
                    if self_key_id != expected_self_key_id {
                        println!("WARNING: Self keyId mismatch! our key is {} but message expects {}", self_key_id, expected_self_key_id);
                    }

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

// Resolve a MID to its displayName, with caching.
// MIDs starting with 'c' are chat/group MIDs → use getChats (Chat field 6 = chatName).
// Other MIDs are user MIDs → use getContact (Contact field 22 = displayName, 27 = overridden).
async fn resolve_display_name(
    mid: &str,
    talk_service: &TalkService,
    cache: &mut HashMap<String, String>,
) -> String {
    if mid.is_empty() {
        return String::new();
    }
    if let Some(name) = cache.get(mid) {
        return name.clone();
    }

    if mid.starts_with('c') {
        // Chat/group MID → use getChats to get chatName
        match talk_service.get_chats(&[mid]).await {
            Ok(resp) => {
                // GetChatsResponse field 1 = chats (list of Chat)
                // Chat field 6 = chatName
                if let Some(chats) = resp.get("1").and_then(|v| v.as_array()) {
                    if let Some(chat) = chats.first() {
                        let name = chat.get("6")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .unwrap_or(mid)
                            .to_string();
                        cache.insert(mid.to_string(), name.clone());
                        return name;
                    }
                }
                cache.insert(mid.to_string(), mid.to_string());
                mid.to_string()
            }
            Err(e) => {
                println!("Warning: Failed to resolve chatName for {}: {}", mid, e);
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
                cache.insert(mid.to_string(), name.clone());
                name
            }
            Err(e) => {
                println!("Warning: Failed to resolve displayName for {}: {}", mid, e);
                cache.insert(mid.to_string(), mid.to_string());
                mid.to_string()
            }
        }
    }
}

// Get peer's E2EE public key, using cache or calling negotiateE2EEPublicKey.
// Returns (keyId, keyData).
async fn get_peer_public_key(
    mid: &str,
    talk_service: &TalkService,
    cache: &mut HashMap<String, (i64, Vec<u8>)>,
) -> Option<(i64, Vec<u8>)> {
    if let Some(entry) = cache.get(mid) {
        return Some(entry.clone());
    }

    match talk_service.negotiate_e2ee_public_key(mid).await {
        Ok((key_id, key_data)) => {
            println!("DEBUG: negotiate keyId={} for mid={} pubKey[..4]={:02x?}",
                key_id, mid, &key_data[..4.min(key_data.len())]);
            cache.insert(mid.to_string(), (key_id, key_data.clone()));
            Some((key_id, key_data))
        }
        Err(e) => {
            println!("Failed to get E2EE public key for {}: {}", mid, e);
            None
        }
    }
}
