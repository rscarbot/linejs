use crate::request::{RequestClient, RequestError};
use crate::thrift::{CompactProtocol, BinaryProtocol, TType};
use std::io::Cursor;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, BigUint};
use rand::rngs::OsRng;

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Thrift error: {0}")]
    Thrift(#[from] crate::thrift::ThriftError),
    #[error("Request error: {0}")]
    Request(#[from] RequestError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Login failed: {0}")]
    Failed(String),
}

pub struct Login {
    pub client: RequestClient,
}

// Long polling timeout for checkQrCodeVerified/checkPinCodeVerified (180 seconds)
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(180);

impl Login {
    pub fn new(client: RequestClient) -> Self { Self { client } }

    // Extract a string result from Thrift response by field ID
    fn get_result(val: &serde_json::Value, fid: &str) -> Option<String> {
        if let Some(v) = val.get(fid).and_then(|v| v.as_str()) { return Some(v.to_string()); }
        if let Some(v) = val.get("0").and_then(|v| v.get(fid)).and_then(|v| v.as_str()) { return Some(v.to_string()); }
        None
    }

    // Check for Thrift exception in response (field "1" = exception struct)
    fn check_exception(val: &serde_json::Value) -> Result<(), LoginError> {
        if let Some(e) = val.get("1") {
            if e.is_object() {
                let msg = e.get("2").and_then(|v| v.as_str()).unwrap_or("Unknown error");
                return Err(LoginError::Failed(msg.to_string()));
            }
        }
        Ok(())
    }

    // Parse compact protocol Thrift response and check message_type for EXCEPTION (3) vs REPLY (2).
    fn parse_response(bytes: &[u8]) -> Result<(u8, serde_json::Value), LoginError> {
        if bytes.is_empty() {
            return Err(LoginError::Failed("Empty response".to_string()));
        }
        let mut proto = CompactProtocol::new(Some(Cursor::new(bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        let val = proto.read_struct_to_value()?;

        if message_type == 3 {
            let msg = val.get("1")
                .and_then(|v| v.as_str())
                .unwrap_or("Thrift exception");
            return Err(LoginError::Failed(msg.to_string()));
        }

        Self::check_exception(&val)?;
        Ok((message_type, val))
    }

    // Parse binary protocol Thrift response (used by /api/v3/TalkService.do and /api/v3p/rs).
    fn parse_binary_response(bytes: &[u8]) -> Result<(u8, serde_json::Value), LoginError> {
        if bytes.is_empty() {
            return Err(LoginError::Failed("Empty response".to_string()));
        }
        let mut proto = BinaryProtocol::new(Some(Cursor::new(bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        let val = proto.read_struct_to_value()?;

        if message_type == 3 {
            let msg = val.get("1")
                .and_then(|v| v.as_str())
                .unwrap_or("Thrift exception");
            return Err(LoginError::Failed(msg.to_string()));
        }

        Self::check_exception(&val)?;
        Ok((message_type, val))
    }

    pub async fn create_session(&self) -> Result<String, LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0d];
        body.extend_from_slice(b"createSession");
        body.push(0x00);

        let res = self.client.post_thrift("/acct/lgn/sq/v1", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_response(&bytes)?;
        if let Some(sid) = Self::get_result(&val, "1") { return Ok(sid); }
        Err(LoginError::Failed("Session ID not found".to_string()))
    }

    pub async fn create_qr_code(&self, session_id: &str) -> Result<String, LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0c];
        body.extend_from_slice(b"createQrCode");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/acct/lgn/sq/v1", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_response(&bytes)?;
        if let Some(url) = Self::get_result(&val, "1") { return Ok(url); }
        Err(LoginError::Failed("QR Code URL not found".to_string()))
    }

    // Single blocking long-poll to check if the QR code has been scanned.
    // Returns true if verified, false if timed out (no scan within timeout period).
    // Uses 180s timeout to match TypeScript's longTimeout config.
    pub async fn check_qr_code_verified(&self, session_id: &str) -> Result<bool, LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x13];
        body.extend_from_slice(b"checkQrCodeVerified");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let mut headers = HashMap::new();
        headers.insert("x-lst".to_string(), "180000".to_string());
        headers.insert("x-line-access".to_string(), session_id.to_string());

        // Long-poll: blocks until QR scan or server timeout
        let res = match self.client.post_thrift_with_timeout(
            "/acct/lp/lgn/sq/v1", body, Some(headers), Some(LONG_POLL_TIMEOUT)
        ).await {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        let bytes = res.bytes().await?;
        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        let val = proto.read_struct_to_value()?;

        // message_type 2 = REPLY (success), field "0" must exist for verified
        // message_type 3 = EXCEPTION (timeout or error)
        if message_type == 2 && !val.get("1").map_or(false, |v| v.is_object()) {
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn verify_certificate(&self, session_id: &str, cert: Option<&str>) -> Result<(), LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x11];
        body.extend_from_slice(b"verifyCertificate");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            if let Some(c) = cert {
                proto.write_field_begin(TType::String, 2)?;
                proto.write_string(c)?;
            }
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/acct/lgn/sq/v1", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, _val) = Self::parse_response(&bytes)?;
        Ok(())
    }

    // Login result containing auth token and raw response for E2EE key extraction
    pub async fn qr_code_login(&self, session_id: &str) -> Result<(String, serde_json::Value), LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0b];
        body.extend_from_slice(b"qrCodeLogin");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            proto.write_field_begin(TType::String, 2)?;
            proto.write_string(self.client.device_details.device_type.as_str())?;
            proto.write_field_begin(TType::Bool, 3)?;
            proto.write_bool(true)?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/acct/lgn/sq/v1", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_response(&bytes)?;
        if let Some(token) = Self::get_result(&val, "2") {
            return Ok((token, val));
        }
        Err(LoginError::Failed("Auth token not found".to_string()))
    }

    pub async fn create_pin_code(&self, session_id: &str) -> Result<String, LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0d];
        body.extend_from_slice(b"createPinCode");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/acct/lgn/sq/v1", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_response(&bytes)?;
        if let Some(pin) = Self::get_result(&val, "1") { return Ok(pin); }
        Err(LoginError::Failed("Pincode not found".to_string()))
    }

    // Single blocking long-poll to check if pincode has been verified.
    // Returns true if verified, false if timed out.
    pub async fn check_pin_code_verified(&self, session_id: &str) -> Result<bool, LoginError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x14];
        body.extend_from_slice(b"checkPinCodeVerified");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(session_id)?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let mut headers = HashMap::new();
        headers.insert("x-lst".to_string(), "180000".to_string());
        headers.insert("x-line-access".to_string(), session_id.to_string());

        // Long-poll: blocks until pincode verification or server timeout
        let res = match self.client.post_thrift_with_timeout(
            "/acct/lp/lgn/sq/v1", body, Some(headers), Some(LONG_POLL_TIMEOUT)
        ).await {
            Ok(r) => r,
            Err(_) => return Ok(false),
        };

        let bytes = res.bytes().await?;
        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        let val = proto.read_struct_to_value()?;

        // message_type 2 = REPLY (success), no exception field means verified
        if message_type == 2 && !val.get("1").map_or(false, |v| v.is_object()) {
            return Ok(true);
        }

        Ok(false)
    }

    // ── Email / Password Login ──────────────────────────────────────────

    /// Fetch RSA public key from the server for encrypting email credentials.
    /// Returns (keynm, nvalue_hex, evalue_hex, sessionKey).
    /// Uses TBinaryProtocol (protocol type 3) matching the TypeScript implementation.
    pub async fn get_rsa_key_info(&self) -> Result<(String, String, String, String), LoginError> {
        let mut body = Vec::new();
        {
            let mut proto = BinaryProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_message_begin("getRSAKeyInfo", 1, 0)?; // CALL=1, seqId=0
            // args field 1 = struct { field 2 = i32(0) } (IdentityProvider = LINE)
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_field_begin(TType::I32, 2)?;
            proto.write_i32(0)?;
            proto.write_field_stop()?; // end inner struct
            proto.write_field_stop()?; // end args struct
        }
        body.push(0x00);

        let res = self.client.post_thrift("/api/v3/TalkService.do", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_binary_response(&bytes)?;

        // RSAKey is in field 0 (success) of the result struct
        let key = val.get("0").unwrap_or(&val);
        let keynm = key.get("1").and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("keynm not found".to_string()))?;
        let nvalue = key.get("2").and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("nvalue not found".to_string()))?;
        let evalue = key.get("3").and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("evalue not found".to_string()))?;
        let session_key = key.get("4").and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("sessionKey not found".to_string()))?;

        Ok((keynm.to_string(), nvalue.to_string(), evalue.to_string(), session_key.to_string()))
    }

    /// RSA-encrypt the login credentials (sessionKey + email + password).
    /// Returns the encrypted message as a hex string.
    pub fn rsa_encrypt_credentials(
        nvalue_hex: &str,
        evalue_hex: &str,
        session_key: &str,
        email: &str,
        password: &str,
    ) -> Result<String, LoginError> {
        // Build message: chr(sessionKey.len) + sessionKey + chr(email.len) + email + chr(password.len) + password
        let mut message = Vec::new();
        message.push(session_key.len() as u8);
        message.extend_from_slice(session_key.as_bytes());
        message.push(email.len() as u8);
        message.extend_from_slice(email.as_bytes());
        message.push(password.len() as u8);
        message.extend_from_slice(password.as_bytes());

        // Parse RSA public key from hex (proactively pad with 0 if odd length)
        let n_hex = if nvalue_hex.len() % 2 != 0 { format!("0{}", nvalue_hex) } else { nvalue_hex.to_string() };
        let e_hex = if evalue_hex.len() % 2 != 0 { format!("0{}", evalue_hex) } else { evalue_hex.to_string() };

        let n = BigUint::from_bytes_be(&hex::decode(&n_hex)
            .map_err(|e| LoginError::Failed(format!("Invalid nvalue hex: {}", e)))?);
        let e = BigUint::from_bytes_be(&hex::decode(&e_hex)
            .map_err(|e| LoginError::Failed(format!("Invalid evalue hex: {}", e)))?);
        let pub_key = RsaPublicKey::new(n, e)
            .map_err(|e| LoginError::Failed(format!("Invalid RSA key: {}", e)))?;

        // PKCS1v1.5 encrypt
        let mut rng = OsRng;
        let encrypted = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &message)
            .map_err(|e| LoginError::Failed(format!("RSA encrypt failed: {}", e)))?;

        Ok(hex::encode(encrypted))
    }

    /// Call loginZ to authenticate with encrypted email/password credentials.
    /// Returns the full LoginResult as JSON value.
    /// LoginResult fields: 1=authToken, 2=certificate, 3=verifier, 4=pinCode
    /// Uses TBinaryProtocol (protocol type 3) matching the TypeScript implementation.
    ///
    /// loginType logic (matching TS loginV2):
    ///   2 = e2ee_data provided but no verifier (initial E2EE login)
    ///   1 = verifier provided (PIN-verified re-call)
    ///   0 = neither (non-E2EE login)
    pub async fn login_z(
        &self,
        keynm: &str,
        encrypted_message: &str,
        device_name: &str,
        cert: Option<&str>,
        verifier: Option<&str>,
        e2ee_data: Option<&[u8]>,
    ) -> Result<serde_json::Value, LoginError> {
        let login_type: i32 = if verifier.is_some() {
            1
        } else if e2ee_data.is_some() {
            2
        } else {
            0
        };

        let mut body = Vec::new();
        {
            let mut proto = BinaryProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_message_begin("loginZ", 1, 0)?; // CALL=1, seqId=0
            // args field 2 = LoginRequest struct
            proto.write_field_begin(TType::Struct, 2)?;

            // field 1: loginType (i32)
            proto.write_field_begin(TType::I32, 1)?;
            proto.write_i32(login_type)?;
            // field 2: identityProvider (i32) = 1 (LINE)
            proto.write_field_begin(TType::I32, 2)?;
            proto.write_i32(1)?;
            // field 3: keynm (string)
            proto.write_field_begin(TType::String, 3)?;
            proto.write_string(keynm)?;
            // field 4: encryptedMessage (string)
            proto.write_field_begin(TType::String, 4)?;
            proto.write_string(encrypted_message)?;
            // field 5: keepLoggedIn (bool) = false
            proto.write_field_begin(TType::Bool, 5)?;
            proto.write_bool(false)?;
            // field 6: accessLocation (string) = ""
            proto.write_field_begin(TType::String, 6)?;
            proto.write_string("")?;
            // field 7: deviceName (string)
            proto.write_field_begin(TType::String, 7)?;
            proto.write_string(device_name)?;
            // field 8: certificate (string, optional)
            if let Some(c) = cert {
                proto.write_field_begin(TType::String, 8)?;
                proto.write_string(c)?;
            }
            // field 9: verifier (string, optional)
            if let Some(v) = verifier {
                proto.write_field_begin(TType::String, 9)?;
                proto.write_string(v)?;
            }
            // field 10: e2eeData (binary, optional)
            if let Some(data) = e2ee_data {
                proto.write_field_begin(TType::String, 10)?;
                proto.write_binary(data)?;
            }
            // field 11: e2eeVersion (i32) = 1
            proto.write_field_begin(TType::I32, 11)?;
            proto.write_i32(1)?;
            // field 12: systemName (string)
            proto.write_field_begin(TType::String, 12)?;
            proto.write_string("System Product Name")?;

            proto.write_field_stop()?; // end LoginRequest struct
            proto.write_field_stop()?; // end args struct
        }
        body.push(0x00);

        let res = self.client.post_thrift("/api/v3p/rs", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_binary_response(&bytes)?;

        // LoginResult is in field 0 (success)
        let result = val.get("0").unwrap_or(&val);
        Ok(result.clone())
    }

    /// Poll GET /Q to wait for PIN code verification during non-E2EE email login.
    /// Returns the verifier string from the server response.
    pub async fn poll_email_pin_verified(&self, verifier_token: &str) -> Result<String, LoginError> {
        let mut headers = HashMap::new();
        headers.insert("accept".to_string(), "application/x-thrift".to_string());
        headers.insert("x-line-access".to_string(), verifier_token.to_string());

        let res = self.client.get_with_headers("/Q", headers, Some(LONG_POLL_TIMEOUT)).await
            .map_err(|e| LoginError::Failed(format!("PIN verification poll failed: {}", e)))?;
        let text = res.text().await
            .map_err(|e| LoginError::Failed(format!("Failed to read PIN response: {}", e)))?;

        // Response is JSON: { result: { verifier: "..." } }
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| LoginError::Failed(format!("Invalid PIN response JSON: {}", e)))?;

        let new_verifier = json.get("result")
            .and_then(|r| r.get("verifier"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("Verifier not found in PIN response".to_string()))?;

        Ok(new_verifier.to_string())
    }

    /// Poll GET /LF1 to wait for E2EE PIN verification during email login.
    /// Returns the full JSON result containing metadata (publicKey, encryptedKeyChain, etc).
    /// Matching TS: fetch(`/LF1`, { headers: { "x-line-access": verifier } })
    pub async fn poll_email_e2ee_info(&self, verifier_token: &str) -> Result<serde_json::Value, LoginError> {
        let mut headers = HashMap::new();
        headers.insert("x-line-access".to_string(), verifier_token.to_string());

        let res = self.client.get_with_headers("/LF1", headers, Some(LONG_POLL_TIMEOUT)).await
            .map_err(|e| LoginError::Failed(format!("E2EE info poll failed: {}", e)))?;
        let text = res.text().await
            .map_err(|e| LoginError::Failed(format!("Failed to read E2EE info response: {}", e)))?;

        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| LoginError::Failed(format!("Invalid E2EE info JSON: {}", e)))?;

        let result = json.get("result")
            .ok_or_else(|| LoginError::Failed("No result in E2EE info response".to_string()))?;

        Ok(result.clone())
    }

    /// Call confirmE2EELogin with verifier and deviceSecret.
    /// Returns the new verifier string for the final loginZ call.
    /// Matching TS: confirmE2EELogin(verifier, deviceSecret) → thrift to /api/v3p/rs
    pub async fn confirm_e2ee_login(&self, verifier: &str, device_secret: &[u8]) -> Result<String, LoginError> {
        let mut body = Vec::new();
        {
            let mut proto = BinaryProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_message_begin("confirmE2EELogin", 1, 0)?;
            // field 1: verifier (string)
            proto.write_field_begin(TType::String, 1)?;
            proto.write_string(verifier)?;
            // field 2: deviceSecret (binary)
            proto.write_field_begin(TType::String, 2)?;
            proto.write_binary(device_secret)?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/api/v3p/rs", body, None).await?;
        let bytes = res.bytes().await?;
        let (_msg_type, val) = Self::parse_binary_response(&bytes)?;

        // Field 0 = success (the new verifier string)
        let new_verifier = val.get("0")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LoginError::Failed("No verifier from confirmE2EELogin".to_string()))?;

        Ok(new_verifier.to_string())
    }
}
