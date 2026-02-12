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

        // Decrypt the key chain
        let keychain_data = Self::decrypt_aes_cbc(&aes_key, &aes_iv, &encrypted_key_chain)?;

        // Parse Thrift struct to extract privKey and pubKey.
        // The key chain is a Thrift struct containing a nested struct
        // at field 1, which has pubKey at subfield 4 and privKey at subfield 5.
        let mut cursor = std::io::Cursor::new(&keychain_data);
        let mut proto = crate::thrift::CompactProtocol::new(
            Some(&mut cursor), None::<&mut Vec<u8>>
        );
        let val = proto.read_struct_to_value()
            .map_err(|e| format!("parse key chain Thrift: {}", e))?;

        // Navigate: val["1"] is a list, first element has fields "4" (pubKey) and "5" (privKey)
        let inner = val.get("1")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .ok_or("key chain: missing inner struct")?;

        // Extract pubKey (field 4) and privKey (field 5) as base64 strings
        let pub_key_b64 = inner.get("4")
            .and_then(|v| v.as_str())
            .ok_or("key chain: missing pubKey")?;
        let priv_key_b64 = inner.get("5")
            .and_then(|v| v.as_str())
            .ok_or("key chain: missing privKey")?;

        let pub_key = general_purpose::STANDARD.decode(pub_key_b64)
            .map_err(|e| format!("decode pubKey: {}", e))?;
        let priv_key = general_purpose::STANDARD.decode(priv_key_b64)
            .map_err(|e| format!("decode privKey: {}", e))?;

        Ok(E2EEKeyData {
            key_id: key_id.to_string(),
            priv_key,
            pub_key,
            e2ee_version: e2ee_version.to_string(),
        })
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
