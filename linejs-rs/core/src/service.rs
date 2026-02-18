use crate::request::{RequestClient, RequestError};
use crate::thrift::{CompactProtocol, TType};
use std::io::Cursor;
use std::time::Duration;

// Error type for TalkService operations
#[derive(Debug)]
pub enum ServiceError {
    Request(RequestError),
    Thrift(crate::thrift::ThriftError),
    Http(reqwest::Error),
    Failed(String),
}

impl From<RequestError> for ServiceError {
    fn from(e: RequestError) -> Self { ServiceError::Request(e) }
}

impl From<crate::thrift::ThriftError> for ServiceError {
    fn from(e: crate::thrift::ThriftError) -> Self { ServiceError::Thrift(e) }
}

impl From<reqwest::Error> for ServiceError {
    fn from(e: reqwest::Error) -> Self { ServiceError::Http(e) }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ServiceError::Request(e) => write!(f, "Request: {}", e),
            ServiceError::Thrift(e) => write!(f, "Thrift: {}", e),
            ServiceError::Http(e) => write!(f, "Http: {}", e),
            ServiceError::Failed(e) => write!(f, "Failed: {}", e),
        }
    }
}

// Long-polling timeout for sync endpoint
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

// Sync state tracking revision cursors for incremental polling
pub struct SyncState {
    pub revision: i64,
    pub global_rev: i64,
    pub individual_rev: i64,
}

impl SyncState {
    pub fn new() -> Self {
        SyncState { revision: 0, global_rev: 0, individual_rev: 0 }
    }
}

pub struct TalkService {
    pub client: RequestClient,
}

impl TalkService {
    pub fn new(client: RequestClient) -> Self { Self { client } }

    // Negotiate E2EE public key for a peer midto get their keyData.
    // negotiateE2EEPublicKey_args: field 2 = mid (string)
    // E2EENegotiationResult: field 2 = publicKey struct (Pb1_C13097n4),
    //   field 3 = specVersion (i32)
    // Pb1_C13097n4: field 2 = keyId (i32), field 4 = keyData (binary/string)
    pub async fn negotiate_e2ee_public_key(&self, mid: &str) -> Result<(i64, Vec<u8>), ServiceError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x16];
        body.extend_from_slice(b"negotiateE2EEPublicKey");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            // field 2 = mid (string)
            proto.write_field_begin(TType::String, 2)?;
            proto.write_string(mid)?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/S4", body, None).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
            return Err(ServiceError::Failed("Empty negotiate response".to_string()));
        }

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("Negotiate exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;
        println!("DEBUG negotiate raw response: {}", serde_json::to_string(&val).unwrap_or_default());

        // result field 0 = success (E2EENegotiationResult)
        let success = val.get("0")
            .ok_or_else(|| ServiceError::Failed("No negotiate result".to_string()))?;

        // E2EENegotiationResult field 2 = publicKey struct
        let pub_key_struct = success.get("2")
            .ok_or_else(|| ServiceError::Failed("No publicKey in negotiate result".to_string()))?;

        // Pb1_C13097n4 field 2 = keyId (i32), field 4 = keyData (binary as base64 string)
        let key_id = pub_key_struct.get("2").and_then(|v| v.as_i64()).unwrap_or(0);
        let key_data_str = pub_key_struct.get("4").and_then(|v| v.as_str())
            .ok_or_else(|| ServiceError::Failed("No keyData in negotiate result".to_string()))?;
        println!("DEBUG negotiate: keyId={}, keyData_str_len={}, keyData_str[..40]={:?}",
            key_id, key_data_str.len(), &key_data_str[..40.min(key_data_str.len())]);

        // Thrift reader stores valid-UTF-8 binary as plain strings, non-UTF-8 as base64.
        // Try base64 decode first; if it fails, the string IS the raw UTF-8 bytes.
        let key_data = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD, key_data_str
        ) {
            Ok(bytes) => bytes,
            Err(_) => key_data_str.as_bytes().to_vec(),
        };

        Ok((key_id, key_data))
    }

    // Get the user's own registered E2EE public keys.
    // Returns a list of (keyId, keyData_bytes) pairs.
    // Matching TS: getE2EEPublicKeys() → list of E2EEPublicKey structs
    pub async fn get_e2ee_public_keys(&self) -> Result<Vec<(i64, Vec<u8>)>, ServiceError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x12];
        body.extend_from_slice(b"getE2EEPublicKeys");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/S4", body, None).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
            return Err(ServiceError::Failed("Empty getE2EEPublicKeys response".to_string()));
        }

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("getE2EEPublicKeys exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;
        // Field 0 = success (list of E2EEPublicKey structs)
        let list = val.get("0").and_then(|v| v.as_array())
            .ok_or_else(|| ServiceError::Failed("No keys in getE2EEPublicKeys result".to_string()))?;

        let mut keys = Vec::new();
        for item in list {
            let key_id = item.get("2").and_then(|v| v.as_i64()).unwrap_or(0);
            if let Some(key_data_str) = item.get("4").and_then(|v| v.as_str()) {
                let key_data = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD, key_data_str
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => key_data_str.as_bytes().to_vec(),
                };
                keys.push((key_id, key_data));
            }
        }

        Ok(keys)
    }

    pub async fn get_profile(&self) -> Result<serde_json::Value, ServiceError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0a];
        body.extend_from_slice(b"getProfile");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            proto.write_struct_begin()?;
            proto.write_field_stop()?;
            proto.write_struct_end()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/S4", body, None).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
             return Err(ServiceError::Failed("Empty getProfile response".to_string()));
        }

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("getProfile exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;
        let success = val.get("0")
            .ok_or_else(|| ServiceError::Failed("No result in getProfile".to_string()))?;
        
        Ok(success.clone())
    }

    /// Get contact info by MID. Returns the Contact struct as JSON.
    /// Contact field 1 = mid, field 22 = displayName, field 27 = displayNameOverridden.
    pub async fn get_contact(&self, mid: &str) -> Result<serde_json::Value, ServiceError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x0a];
        body.extend_from_slice(b"getContact");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));
            // field 2 = mid (string)
            proto.write_field_begin(TType::String, 2)?;
            proto.write_string(mid)?;
            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/S4", body, None).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
            return Err(ServiceError::Failed("Empty getContact response".to_string()));
        }

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("getContact exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;
        let success = val.get("0")
            .ok_or_else(|| ServiceError::Failed("No result in getContact".to_string()))?;

        Ok(success.clone())
    }

    /// Get chat info by chat MID(s). Returns GetChatsResponse as JSON.
    /// GetChatsResponse field 1 = chats (list of Chat).
    /// Chat: field 2 = chatMid (string), field 6 = chatName (string).
    /// getChats_args: field 1 = GetChatsRequest (struct), field 2 = syncReason (i32 enum).
    /// GetChatsRequest: field 1 = chatMids (list<string>), field 2 = withMembers (bool), field 3 = withInvitees (bool).
    pub async fn get_chats(&self, chat_mids: &[&str]) -> Result<serde_json::Value, ServiceError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x08];
        body.extend_from_slice(b"getChats");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));

            // field 1 = GetChatsRequest (struct)
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;

            // GetChatsRequest.chatMids: field 1, list<string>
            proto.write_field_begin(TType::List, 1)?;
            proto.write_list_begin(TType::String, chat_mids.len())?;
            for mid in chat_mids {
                proto.write_string(mid)?;
            }

            // GetChatsRequest.withMembers: field 2, bool = false
            proto.write_field_begin(TType::Bool, 2)?;
            proto.write_bool(false)?;

            // GetChatsRequest.withInvitees: field 3, bool = false
            proto.write_field_begin(TType::Bool, 3)?;
            proto.write_bool(false)?;

            proto.write_field_stop()?;
            proto.write_struct_end()?;

            // field 2 = syncReason (i32 enum Pb1_V7, 7 = INTERNAL)
            proto.write_field_begin(TType::I32, 2)?;
            proto.write_i32(7)?;

            proto.write_field_stop()?;
        }
        body.push(0x00);

        let res = self.client.post_thrift("/S4", body, None).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
            return Err(ServiceError::Failed("Empty getChats response".to_string()));
        }

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("getChats exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;
        let success = val.get("0")
            .ok_or_else(|| ServiceError::Failed("No result in getChats".to_string()))?;

        Ok(success.clone())
    }

    // Build the sync Thrift request body matching TypeScript's sync_args structure:
    // [12, 1, SyncRequest{ lastRevision(i64 f1), count(i32 f2),
    //   lastGlobalRevision(i64 f3), lastIndividualRevision(i64 f4) }]
    fn build_sync_body(state: &SyncState, count: i32) -> Result<Vec<u8>, crate::thrift::ThriftError> {
        let mut body = vec![0x82, 0x21, 0x00, 0x04];
        body.extend_from_slice(b"sync");
        {
            let mut proto = CompactProtocol::new(None::<Cursor<&[u8]>>, Some(&mut body));

            // sync_args: field 1 = SyncRequest (struct)
            proto.write_field_begin(TType::Struct, 1)?;
            proto.write_struct_begin()?;

            // SyncRequest.lastRevision: field 1, type i64
            proto.write_field_begin(TType::I64, 1)?;
            proto.write_i64(state.revision)?;

            // SyncRequest.count: field 2, type i32
            proto.write_field_begin(TType::I32, 2)?;
            proto.write_i32(count)?;

            // SyncRequest.lastGlobalRevision: field 3, type i64
            proto.write_field_begin(TType::I64, 3)?;
            proto.write_i64(state.global_rev)?;

            // SyncRequest.lastIndividualRevision: field 4, type i64
            proto.write_field_begin(TType::I64, 4)?;
            proto.write_i64(state.individual_rev)?;

            proto.write_field_stop()?;
            proto.write_struct_end()?;
            proto.write_field_stop()?;
        }
        body.push(0x00);
        Ok(body)
    }

    // Perform a sync call and return the parsed response.
    // Updates SyncState with new revision cursors from the response.
    // Returns list of operations (each as serde_json::Value).
    pub async fn sync(&self, state: &mut SyncState) -> Result<Vec<serde_json::Value>, ServiceError> {
        let body = Self::build_sync_body(state, 100)?;

        let res = self.client.post_thrift_with_timeout(
            "/SYNC4", body, None, Some(SYNC_TIMEOUT)
        ).await?;
        let bytes = res.bytes().await?;

        if bytes.is_empty() {
            return Ok(vec![]);
        }

        // Log response bytes for diagnostic (truncated to first 500 bytes)
        let display_len = bytes.len().min(500);
        println!("[DEBUG] Response {} bytes (showing first {}): {}",
            bytes.len(), display_len, hex::encode(&bytes[..display_len]));

        let mut proto = CompactProtocol::new(Some(Cursor::new(&bytes)), None::<&mut Vec<u8>>);
        let (_name, message_type, _seq) = proto.read_message_begin()?;

        // message_type 3 = EXCEPTION
        if message_type == 3 {
            let val = proto.read_struct_to_value()?;
            let msg = val.get("1").and_then(|v| v.as_str()).unwrap_or("Sync exception");
            return Err(ServiceError::Failed(msg.to_string()));
        }

        let val = proto.read_struct_to_value()?;

        // sync_result field 0 = success (Pb1_X7)
        let success = match val.get("0") {
            Some(s) => s,
            None => {
                // Check for TalkException in field 1
                if let Some(e) = val.get("1") {
                    let msg = e.get("2").and_then(|v| v.as_str()).unwrap_or("TalkException");
                    return Err(ServiceError::Failed(msg.to_string()));
                }
                return Ok(vec![]);
            }
        };

        // Handle fullSyncResponse (field 2): update revision to nextRevision
        if let Some(full_sync) = success.get("2") {
            if let Some(next_rev) = full_sync.get("2").and_then(|v| v.as_i64()) {
                state.revision = next_rev;
            }
        }

        // Handle operationResponse (field 1)
        let op_response = match success.get("1") {
            Some(v) => v,
            None => return Ok(vec![]),
        };

        // Update globalRev from TGlobalEvents (field 3)
        if let Some(global_events) = op_response.get("3") {
            if let Some(last_rev) = global_events.get("2").and_then(|v| v.as_i64()) {
                state.global_rev = last_rev;
            }
        }

        // Update individualRev from TIndividualEvents (field 4)
        if let Some(individual_events) = op_response.get("4") {
            if let Some(last_rev) = individual_events.get("2").and_then(|v| v.as_i64()) {
                state.individual_rev = last_rev;
            }
        }

        // Extract operations list (field 1 of OperationResponse)
        let operations = match op_response.get("1").and_then(|v| v.as_array()) {
            Some(ops) => {
                // Update revision from each operation
                for op in ops {
                    if let Some(rev) = op.get("1").and_then(|v| v.as_i64()) {
                        if rev > state.revision {
                            state.revision = rev;
                        }
                    }
                }
                ops.clone()
            }
            None => vec![],
        };

        Ok(operations)
    }
}
