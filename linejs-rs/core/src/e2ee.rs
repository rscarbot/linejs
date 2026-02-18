use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey, StaticSecret};
use base64::{Engine as _, engine::general_purpose};
use urlencoding::encode;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;

// E2EE key data extracted from login response
#[derive(Debug, Clone)]
pub struct E2EEKeyData {
    pub key_id: String,
    pub priv_key: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub e2ee_version: String,
}

pub struct E2EE {}

impl E2EE {
    // Generate X25519 keypair for SQR login (uses StaticSecret for byte extraction)
    pub fn create_sqr_secret() -> (StaticSecret, String) {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);

        let pub_key_base64 = general_purpose::STANDARD.encode(public_key.as_bytes());
        let secret_param = encode(&pub_key_base64);

        (secret_key, format!("?secret={}&e2eeVersion=1", secret_param))
    }

    // Generate X25519 keypair for email E2EE login.
    // Returns (secret_key_bytes, public_key_base64) matching TS createSqrSecret(true).
    pub fn create_sqr_secret_raw() -> (Vec<u8>, String) {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        let pub_key_base64 = general_purpose::STANDARD.encode(public_key.as_bytes());
        (secret_key.as_bytes().to_vec(), pub_key_base64)
    }

    // AES-256-ECB encrypt with no padding (matching TS encryptAESECB).
    // Key must be 32 bytes, data must be a multiple of 16 bytes.
    pub fn encrypt_aes_ecb(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        use aes::cipher::{BlockEncrypt, generic_array::GenericArray};
        if data.len() % 16 != 0 {
            return Err(format!("AES-ECB: data length {} not multiple of 16", data.len()));
        }
        let cipher = aes::Aes256::new_from_slice(key)
            .map_err(|e| format!("AES-ECB key init: {}", e))?;
        let mut result = data.to_vec();
        for chunk in result.chunks_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }
        Ok(result)
    }

    // Encrypt device secret for confirmE2EELogin (matching TS encryptDeviceSecret).
    // Arguments: server_public_key (raw bytes), secret_key (raw bytes), encrypted_key_chain (raw bytes).
    pub fn encrypt_device_secret(
        server_public_key: &[u8],
        secret_key: &[u8],
        encrypted_key_chain: &[u8],
    ) -> Result<Vec<u8>, String> {
        let shared_secret = Self::generate_shared_secret(secret_key, server_public_key);
        let aes_key = Self::sha256_sum(&[&shared_secret, b"Key"]);
        let chain_hash = Self::sha256_sum(&[encrypted_key_chain]);
        let xored = Self::xor(&chain_hash); // 16 bytes
        Self::encrypt_aes_ecb(&aes_key, &xored)
    }

    // SHA-256 hash of concatenated byte slices
    pub fn sha256_sum(data: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for chunk in data {
            hasher.update(chunk);
        }
        hasher.finalize().to_vec()
    }

    // XOR first half with second half of buffer (for AES-CBC IV derivation)
    pub fn xor(buf: &[u8]) -> Vec<u8> {
        let half = buf.len() / 2;
        let mut result = vec![0u8; half];
        for i in 0..half {
            result[i] = buf[i] ^ buf[half + i];
        }
        result
    }

    // X25519 Diffie-Hellman shared secret (matches curve25519-js sharedKey)
    pub fn generate_shared_secret(private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&private_key[..32]);
        let secret = StaticSecret::from(priv_bytes);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&public_key[..32]);
        let peer_pub = PublicKey::from(pub_bytes);

        let shared = secret.diffie_hellman(&peer_pub);
        shared.as_bytes().to_vec()
    }

    // Decrypt AES-256-CBC (NoPadding to match TS behavior) used for key chain decryption
    fn decrypt_aes_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let mut buf = data.to_vec();
        
        // Ensure data length is a multiple of block size (16)
        if buf.len() % 16 != 0 {
            return Err(format!("AES-CBC decrypt error: data length {} not multiple of 16", buf.len()));
        }

        // Use NoPadding to decrypt everything including padding bytes
        Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init: {}", e))?
            .decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| format!("AES-CBC decrypt: {}", e))?;
            
        Ok(buf)
    }

    // Decode E2EE key from login response metadata using the SQR secret.
    // Decrypts encryptedKeyChain via X25519 shared-secret + AES-256-CBC,
    // then parses the Thrift-encoded key chain to extract privKey and pubKey.
    pub fn decode_e2ee_key_v1(
        encrypted_key_chain_b64: &str,
        server_public_key_b64: &str,
        key_id: &str,
        e2ee_version: &str,
        sqr_secret_key: &[u8],
    ) -> Result<E2EEKeyData, String> {
        let encrypted_key_chain = general_purpose::STANDARD.decode(encrypted_key_chain_b64)
            .map_err(|e| format!("decode encryptedKeyChain: {}", e))?;
        let server_public_key = general_purpose::STANDARD.decode(server_public_key_b64)
            .map_err(|e| format!("decode publicKey: {}", e))?;

        // X25519 shared secret between SQR secret and server's public key
        let shared_secret = Self::generate_shared_secret(sqr_secret_key, &server_public_key);
        let aes_key = Self::sha256_sum(&[&shared_secret, b"Key"]);
        let aes_iv_full = Self::sha256_sum(&[&shared_secret, b"IV"]);
        let aes_iv = Self::xor(&aes_iv_full);

        println!("DEBUG decodeE2EEKeyV1: sqrSecret[..4]={:02x?} serverPub[..4]={:02x?}",
            &sqr_secret_key[..4.min(sqr_secret_key.len())],
            &server_public_key[..4.min(server_public_key.len())]);
        println!("DEBUG decodeE2EEKeyV1: sharedSecret[..8]={:02x?}", &shared_secret[..8]);
        println!("DEBUG decodeE2EEKeyV1: aesKey[..8]={:02x?} aesIv={:02x?}", &aes_key[..8], &aes_iv);

        // Decrypt the key chain
        let keychain_data = Self::decrypt_aes_cbc(&aes_key, &aes_iv, &encrypted_key_chain)?;

        println!("DEBUG decodeE2EEKeyV1: keychain_data({} bytes) hex={}",
            keychain_data.len(), hex::encode(&keychain_data));

        // Parse Thrift key chain directly using raw binary reads to avoid
        // the UTF-8/base64 corruption in read_struct_to_value.
        // Structure: outer struct → field 1 (list of structs) → find element by keyId
        //   → field 4 (pubKey binary), field 5 (privKey binary)
        let target_key_id: i32 = key_id.parse().unwrap_or(0);
        let (pub_key, priv_key) = Self::parse_key_chain_raw(&keychain_data, target_key_id)?;

        println!("DEBUG decodeE2EEKeyV1: pubKey({} bytes)[..4]={:02x?} privKey({} bytes)[..4]={:02x?}",
            pub_key.len(), &pub_key[..4.min(pub_key.len())],
            priv_key.len(), &priv_key[..4.min(priv_key.len())]);

        Ok(E2EEKeyData {
            key_id: key_id.to_string(),
            priv_key,
            pub_key,
            e2ee_version: e2ee_version.to_string(),
        })
    }

    // Parse the decrypted key chain Thrift struct directly using raw binary reads.
    // This avoids the UTF-8/base64 corruption in read_struct_to_value().
    // Iterates through ALL key entries and selects the one matching target_key_id.
    // Returns (pub_key, priv_key) as raw bytes.
    fn parse_key_chain_raw(data: &[u8], target_key_id: i32) -> Result<(Vec<u8>, Vec<u8>), String> {
        use crate::thrift::{CompactProtocol, TType};
        let mut cursor = std::io::Cursor::new(data);
        let mut proto = CompactProtocol::new(
            Some(&mut cursor), None::<&mut Vec<u8>>
        );

        // Read outer struct fields until we find field 1 (list of key structs)
        proto.read_struct_begin().map_err(|e| format!("key chain outer struct: {}", e))?;
        loop {
            let (ttype, fid) = proto.read_field_begin()
                .map_err(|e| format!("key chain field begin: {}", e))?;
            if ttype == TType::Stop { return Err("key chain: field 1 (list) not found".to_string()); }
            if fid == 1 && (ttype == TType::List || ttype == TType::Set) {
                // Read list header
                let header = proto.read_byte_raw()
                    .map_err(|e| format!("key chain list header: {}", e))?;
                let mut size = (header >> 4) as i32;
                if size == 15 {
                    size = proto.read_varint_raw()
                        .map_err(|e| format!("key chain list size: {}", e))? as i32;
                }
                let _etype = header & 0x0f; // should be 0x0C (struct)
                if size < 1 { return Err("key chain: empty key list".to_string()); }

                println!("DEBUG parse_key_chain_raw: list has {} entries, looking for keyId={}",
                    size, target_key_id);

                // Iterate through ALL entries, find the one matching target_key_id
                let mut best_match: Option<(i32, Vec<u8>, Vec<u8>)> = None; // (keyId, pub, priv)
                let mut last_entry: Option<(i32, Vec<u8>, Vec<u8>)> = None;
                for idx in 0..size {
                    let mut entry_key_id: i32 = 0;
                    let mut pub_key: Option<Vec<u8>> = None;
                    let mut priv_key: Option<Vec<u8>> = None;
                    proto.read_struct_begin().map_err(|e| format!("key chain inner struct: {}", e))?;
                    loop {
                        let (ft, fid2) = proto.read_field_begin()
                            .map_err(|e| format!("key chain inner field: {}", e))?;
                        if ft == TType::Stop { break; }
                        if (ft == TType::I32 || ft == TType::I16) && fid2 == 2 {
                            entry_key_id = proto.read_i32()
                                .map_err(|e| format!("key chain keyId read: {}", e))?;
                        } else if ft == TType::String && fid2 == 4 {
                            pub_key = Some(proto.read_binary()
                                .map_err(|e| format!("key chain pubKey read: {}", e))?);
                        } else if ft == TType::String && fid2 == 5 {
                            priv_key = Some(proto.read_binary()
                                .map_err(|e| format!("key chain privKey read: {}", e))?);
                        } else {
                            proto.skip(ft).map_err(|e| format!("key chain skip: {}", e))?;
                        }
                    }
                    proto.read_struct_end().map_err(|e| format!("key chain inner struct end: {}", e))?;

                    if let (Some(ref pk), Some(ref sk)) = (&pub_key, &priv_key) {
                        println!("DEBUG parse_key_chain_raw: entry[{}] keyId={} pubKey[..4]={:02x?}",
                            idx, entry_key_id, &pk[..4.min(pk.len())]);
                        let entry = (entry_key_id, pk.clone(), sk.clone());
                        if entry_key_id == target_key_id {
                            best_match = Some(entry.clone());
                        }
                        last_entry = Some(entry);
                    }
                }

                // Prefer the entry matching target_key_id; fall back to last entry
                let (matched_id, pub_key, priv_key) = best_match
                    .or(last_entry)
                    .ok_or("key chain: no valid key entries found")?;
                println!("DEBUG parse_key_chain_raw: selected keyId={} (target={})",
                    matched_id, target_key_id);
                return Ok((pub_key, priv_key));
            } else {
                proto.skip(ttype).map_err(|e| format!("key chain skip outer: {}", e))?;
            }
        }
    }

    // Build AAD (Additional Authenticated Data) for AES-256-GCM.
    // Format: to_mid + from_mid + senderKeyId(4 bytes BE) + receiverKeyId(4 bytes BE)
    //         + specVersion(4 bytes BE) + contentType(4 bytes BE)
    fn generate_aad(
        to: &str,
        from: &str,
        sender_key_id: i32,
        receiver_key_id: i32,
        spec_version: i32,
        content_type: i32,
    ) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(to.as_bytes());
        aad.extend_from_slice(from.as_bytes());
        aad.extend_from_slice(&sender_key_id.to_be_bytes());
        aad.extend_from_slice(&receiver_key_id.to_be_bytes());
        aad.extend_from_slice(&spec_version.to_be_bytes());
        aad.extend_from_slice(&content_type.to_be_bytes());
        aad
    }

    // Decrypt E2EE message V1 (AES-256-CBC).
    // chunks: [salt, ciphertext, sign, senderKeyId, receiverKeyId(optional)]
    pub fn decrypt_e2ee_message_v1(
        chunks: &[Vec<u8>],
        priv_key: &[u8],
        pub_key: &[u8],
    ) -> Result<serde_json::Value, String> {
        if chunks.len() < 3 {
            return Err(format!("E2EE V1: expected at least 3 chunks, got {}", chunks.len()));
        }

        let salt = &chunks[0];
        let message = &chunks[1];
        let _sign = &chunks[2]; // not used in V1 decryption

        // X25519 shared secret
        let shared_secret = Self::generate_shared_secret(priv_key, pub_key);

        // Derive AES key and IV (matches TS: getSHA256Sum + xor for IV)
        let aes_key = Self::sha256_sum(&[&shared_secret, salt, b"Key"]);
        let aes_iv_full = Self::sha256_sum(&[&shared_secret, salt, b"IV"]);
        let aes_iv = Self::xor(&aes_iv_full);

        println!("DEBUG E2EE V1: salt_len={} msg_len={} aesKey[..8]={:02x?} aesIv[..8]={:02x?}",
            salt.len(), message.len(),
            &aes_key[..8.min(aes_key.len())],
            &aes_iv[..8.min(aes_iv.len())]);

        // Try AES-256-CBC with PKCS7 padding first, fall back to no padding
        let plaintext = match Self::decrypt_aes_cbc_pkcs7(&aes_key, &aes_iv, message) {
            Ok(pt) => pt,
            Err(_) => Self::decrypt_aes_cbc(&aes_key, &aes_iv, message)?,
        };

        let json_str = String::from_utf8(plaintext.clone())
            .or_else(|_| {
                // Try trimming trailing null/padding bytes
                let trimmed = plaintext.iter()
                    .rposition(|&b| b != 0 && b > 0x1f)
                    .map(|pos| &plaintext[..=pos])
                    .unwrap_or(&plaintext);
                String::from_utf8(trimmed.to_vec())
            })
            .map_err(|e| format!("E2EE V1 plaintext not UTF-8: {}", e))?;

        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("E2EE V1 JSON parse: {}", e))?;
        Ok(parsed)
    }

    // AES-256-CBC with PKCS7 padding (default Node.js behavior)
    fn decrypt_aes_cbc_pkcs7(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let mut buf = data.to_vec();

        if buf.is_empty() || buf.len() % 16 != 0 {
            return Err(format!("AES-CBC: data length {} not multiple of 16", buf.len()));
        }

        let result = Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|e| format!("AES-CBC init: {}", e))?
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|e| format!("AES-CBC PKCS7 decrypt: {}", e))?;

        Ok(result.to_vec())
    }

    // Decrypt E2EE message V2 (AES-256-GCM).
    // chunks: [salt, ciphertext+tag, nonce(sign), senderKeyId, receiverKeyId(optional)]
    pub fn decrypt_e2ee_message_v2(
        to: &str,
        from: &str,
        chunks: &[Vec<u8>],
        priv_key: &[u8],
        pub_key: &[u8],
        spec_version: i32,
        content_type: i32,
    ) -> Result<serde_json::Value, String> {
        if chunks.len() < 4 {
            return Err(format!("E2EE: expected at least 4 chunks, got {}", chunks.len()));
        }

        let salt = &chunks[0];
        let message = &chunks[1];
        let sign = &chunks[2];

        // Split message into ciphertext and 16-byte GCM auth tag
        if message.len() < 16 {
            return Err("E2EE: message too short for GCM tag".to_string());
        }
        let ciphertext = &message[..message.len() - 16];
        let tag = &message[message.len() - 16..];

        // Derive sender/receiver key IDs from chunks[3] and chunks[4] (if present)
        let sender_key_id = byte2int(&chunks[3]);
        let receiver_key_id = if chunks.len() > 4 {
            byte2int(&chunks[4])
        } else {
            0
        };

        // X25519 shared secret, then SHA256(sharedSecret + salt + "Key") for GCM key
        let shared_secret = Self::generate_shared_secret(priv_key, pub_key);
        let gcm_key = Self::sha256_sum(&[&shared_secret, salt, b"Key"]);

        // Build AAD
        let aad = Self::generate_aad(
            to, from, sender_key_id, receiver_key_id, spec_version, content_type
        );

        println!("DEBUG E2EE: senderKeyId={} receiverKeyId={} specVer={} contentType={}",
            sender_key_id, receiver_key_id, spec_version, content_type);
        println!("DEBUG E2EE: salt[..8]={:02x?} nonce_len={} ct_len={} tag={:02x?}",
            &salt[..8.min(salt.len())], sign.len(), ciphertext.len(), &tag[..4.min(tag.len())]);
        println!("DEBUG E2EE: sharedSecret[..8]={:02x?}", &shared_secret[..8.min(shared_secret.len())]);
        println!("DEBUG E2EE: gcmKey[..8]={:02x?}", &gcm_key[..8.min(gcm_key.len())]);
        println!("DEBUG E2EE: aad({} bytes)={:02x?}", aad.len(), &aad);

        // AES-256-GCM decrypt: combine ciphertext + tag for aes-gcm crate
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        // Use variable-length nonce support (matches Node.js/OpenSSL behavior)
        let plaintext = decrypt_aes_gcm(&gcm_key, sign, &ct_with_tag, &aad)?;

        let json_str = String::from_utf8(plaintext)
            .map_err(|e| format!("E2EE plaintext not UTF-8: {}", e))?;
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("E2EE JSON parse: {}", e))?;
        Ok(parsed)
    }
}

// Convert 4-byte big-endian buffer to i32 (matches TypeScript byte2int)
fn byte2int(bytes: &[u8]) -> i32 {
    if bytes.len() >= 4 {
        i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        0
    }
}

// AES-256-GCM decryption with a compile-time nonce size type parameter.
fn aes_gcm_decrypt_sized<N>(
    key: &[u8],
    nonce: &[u8],
    ct_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String>
where
    N: aes_gcm::aead::generic_array::ArrayLength<u8>,
{
    let cipher = aes_gcm::AesGcm::<aes::Aes256, N>::new_from_slice(key)
        .map_err(|e| format!("AES-GCM key init: {}", e))?;
    let nonce = aes_gcm::aead::generic_array::GenericArray::<u8, N>::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg: ct_with_tag, aad };
    cipher.decrypt(nonce, payload)
        .map_err(|e| format!("AES-GCM decrypt: {}", e))
}

// AES-256-GCM decryption supporting variable-length nonces (matches Node.js/OpenSSL behavior).
// Non-12-byte nonces are internally processed via GHASH by the aes-gcm crate.
fn decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ct_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::generic_array::typenum;
    match nonce.len() {
        6 => aes_gcm_decrypt_sized::<typenum::U6>(key, nonce, ct_with_tag, aad),
        8 => aes_gcm_decrypt_sized::<typenum::U8>(key, nonce, ct_with_tag, aad),
        12 => aes_gcm_decrypt_sized::<typenum::U12>(key, nonce, ct_with_tag, aad),
        16 => aes_gcm_decrypt_sized::<typenum::U16>(key, nonce, ct_with_tag, aad),
        18 => aes_gcm_decrypt_sized::<typenum::U18>(key, nonce, ct_with_tag, aad),
        24 => aes_gcm_decrypt_sized::<typenum::U24>(key, nonce, ct_with_tag, aad),
        32 => aes_gcm_decrypt_sized::<typenum::U32>(key, nonce, ct_with_tag, aad),
        n => Err(format!("E2EE: unsupported GCM nonce size {} bytes", n)),
    }
}
