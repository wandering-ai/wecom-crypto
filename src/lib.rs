//! # wecom-crypto
//!
//! `wecom-crypto`提供了企业微信API数据的加解密功能。其实现完全遵循官方文档中的规定。
//!
//! ## 使用方法
//! ```
//! use wecom_crypto::{CryptoAgent, CryptoSource};
//!
//! let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
//! let agent = CryptoAgent::new(key);
//! let source = CryptoSource {
//!     text: "hello world!".to_string(),
//!     receive_id: "wandering-ai".to_string(),
//! };
//! let enc = agent.encrypt(&source);
//! let dec = agent.decrypt(enc.as_str()).unwrap();
//! assert_eq!(source, dec);
//! ```
use aes::{
    self,
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes256,
};
use base64::{alphabet, engine, Engine as _};
use cbc::{Decryptor, Encryptor};
use rand;
use sha1::{Digest, Sha1};
use std::error::Error;

/// 根据请求数据生成签名，用于校验微信服务器的请求是否合规。
/// # Example
/// ```
/// use wecom_crypto::generate_signature;
///
/// assert_eq!(
///     generate_signature(vec!["0", "c", "a", "b"]),
///     "a8addbc99f8b3f51d2adbceb605d650b9a8940e2"
/// )
/// ```
pub fn generate_signature(mut inputs: Vec<&str>) -> String {
    inputs.sort_unstable();
    let digest = Sha1::digest(inputs.concat().as_bytes());
    base16ct::lower::encode_string(&digest)
}

/// 加解密数据结构体。
#[derive(PartialEq, Debug)]
pub struct CryptoSource {
    /// 待加密（解密后）的消息。
    pub text: String,
    /// 在企业应用回调中为corpid；在第三方事件回调中为suiteid；在个人主体的第三方应用中为一个空字符串。
    pub receive_id: String,
}

/// 加解密功能代理。是加解密方法的数据结构载体。
#[derive(Clone)]
pub struct CryptoAgent {
    key: [u8; 32],
    nonce: [u8; 16],
    b64: engine::general_purpose::GeneralPurpose,
}

impl CryptoAgent {
    /// 使用给定的AES加密Key初始化代理。参数`key`为BASE64编码后的字符串。
    pub fn new(key: &str) -> Self {
        // The AES key is BASE64 encoded. Be careful this encoding key generated
        // by Tencent is buggy.
        let config = engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent);
        let b64 = engine::GeneralPurpose::new(&alphabet::STANDARD, config);
        let key_as_vec = b64.decode(key).unwrap();
        let key = <[u8; 32]>::try_from(key_as_vec).unwrap();
        let nonce = <[u8; 16]>::try_from(&key[..16]).unwrap();
        Self { key, nonce, b64 }
    }

    /// 加密给定的数据结构体。加密后的字符串为BASE64编码后的数据。
    pub fn encrypt(&self, input: &CryptoSource) -> String {
        // 待加密数据
        let mut block: Vec<u8> = Vec::new();

        // 16字节随机数据
        block.extend(rand::random::<[u8; 16]>());

        // 明文字符串长度
        block.extend((input.text.len() as u32).to_be_bytes());

        // 明文字符串
        block.extend(input.text.as_bytes());

        // Receive ID
        block.extend(input.receive_id.as_bytes());

        // 加密
        let cipher_bytes = Encryptor::<Aes256>::new(&self.key.into(), &self.nonce.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&block);
        self.b64.encode(&cipher_bytes)
    }

    /// 解密BASE64编码的加密数据。解密后的数据为CryptoSource类型。
    pub fn decrypt(&self, encoded: &str) -> Result<CryptoSource, Box<dyn Error>> {
        let cipher_bytes = self
            .b64
            .decode(encoded)
            .map_err(|e| format!("Base64 decode error: {}", e))?;
        let block = Decryptor::<Aes256>::new(&self.key.into(), &self.nonce.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&cipher_bytes)
            .map_err(|e| format!("AES decryption error: {}", e))?;
        let buf = block.as_slice();
        let msg_len: usize = u32::from_be_bytes(buf[16..20].try_into().unwrap()) as usize;
        let text = String::from_utf8(buf[20..20 + msg_len].to_vec())?;
        let receive_id = String::from_utf8(buf[20 + msg_len..].to_vec())?;
        Ok(CryptoSource { text, receive_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signature() {
        assert_eq!(
            generate_signature(vec!["0", "c", "a", "b"]),
            "a8addbc99f8b3f51d2adbceb605d650b9a8940e2",
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
        let agent = CryptoAgent::new(key);
        let source = CryptoSource {
            text: "abcd".to_string(),
            receive_id: "xyz".to_string(),
        };
        let enc = agent.encrypt(&source);
        let dec = agent.decrypt(enc.as_str()).unwrap();
        assert_eq!(source, dec);
    }
}
