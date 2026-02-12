use crate::request::{RequestClient, RequestError};
use crate::thrift::{CompactProtocol, TType};
use std::io::Cursor;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

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

    // Parse Thrift response and check message_type for EXCEPTION (3) vs REPLY (2).
    // Returns (message_type, parsed_struct).
    // Throws LoginError if message_type indicates an exception with error details.
    fn parse_response(bytes: &[u8]) -> Result<(u8, serde_json::Value), LoginError> {
        println!("[DEBUG] Response {} bytes: {}", bytes.len(), hex::encode(bytes));
        if bytes.is_empty() {
            return Err(LoginError::Failed("Empty response".to_string()));
        }
        let mut proto = CompactProtocol::new(Some(Cursor::new(bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        let val = proto.read_struct_to_value()?;

        // message_type 3 = EXCEPTION, also check field "1" for error details
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
}
