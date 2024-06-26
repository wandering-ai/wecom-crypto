//! # wecom-crypto
//!
//! `wecom-crypto`提供了企业微信API数据的加解密功能。其实现完全遵循官方文档中的规定。
//!
//! ## 使用方法
//! ```
//! use wecom_crypto::{Agent, Source};
//!
//! let token = "a";
//! let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
//! let agent = Agent::new(token, key);
//! let source = Source {
//!     text: "hello world!".to_string(),
//!     receive_id: "wandering-ai".to_string(),
//! };
//! let enc = agent.encrypt(&source);
//! let dec = agent.decrypt(enc.as_str()).unwrap();
//! assert_eq!(source, dec);
//! ```

use aes::{
    self,
    cipher::{
        block_padding::{NoPadding, Pkcs7},
        BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    },
    Aes256,
};
use base64::{alphabet, engine, Engine as _};
use cbc::{Decryptor, Encryptor};
use sha1::{Digest, Sha1};
use thiserror::Error;

/// 加解密过程中可能出现的错误
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Wecom decode error. {0}")]
    WecomDecode(String),
    #[error("Base64 decode error. {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("UTF-8 decode error. {0}")]
    Utf8Decode(#[from] std::string::FromUtf8Error),
    #[error("AES decryption error. {0}")]
    AesDecryption(String),
}

/// 生成数据签名，用于校验请求数据是否被篡改。输入需要包含Token。
pub fn generate_sha1_signature(inputs: &[&str]) -> String {
    let mut content = inputs.to_vec();
    content.sort_unstable();
    let digest = Sha1::digest(content.concat().as_bytes());
    base16ct::lower::encode_string(&digest)
}

/// 加解密数据结构体。
#[derive(PartialEq, Debug)]
pub struct Source {
    /// 待加密（解密后）的消息。
    pub text: String,
    /// 在企业应用回调中为corpid；在第三方事件回调中为suiteid；在个人主体的第三方应用中为一个空字符串。
    pub receive_id: String,
}

// AES解密常量化区块大小
const AES_BLOCK_SIZE: usize = 32;

/// 加解密功能代理。是加解密方法的数据结构载体。
#[derive(Clone)]
pub struct Agent {
    token: String,
    key: [u8; AES_BLOCK_SIZE],
    nonce: [u8; 16],
}

impl Agent {
    /// 使用给定的Token和AES加密Key初始化代理。参数`key`为BASE64编码后的字符串。
    pub fn new(token: &str, key: &str) -> Self {
        // The AES key is BASE64 encoded. Be careful this encoding key generated
        // by Tencent is buggy.
        let config = engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent);
        let key_as_vec = engine::GeneralPurpose::new(&alphabet::STANDARD, config)
            .decode(key)
            .expect("AES key should be valid Base64 string");
        let key =
            <[u8; AES_BLOCK_SIZE]>::try_from(key_as_vec).expect("AES key length should be 32");
        let nonce = <[u8; 16]>::try_from(&key[..16]).unwrap();
        Self {
            token: token.to_owned(),
            key,
            nonce,
        }
    }

    /// 根据请求数据生成签名，用于校验微信服务器的请求是否合规。输入数据不需要包含Token。
    /// # Example
    /// ```
    /// use wecom_crypto::Agent;
    ///
    /// let agent = Agent::new("a", "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF");
    /// assert_eq!(
    ///     agent.generate_signature(&["0", "c", "b"]),
    ///     "a8addbc99f8b3f51d2adbceb605d650b9a8940e2"
    /// )
    /// ```
    pub fn generate_signature(&self, inputs: &[&str]) -> String {
        let mut content = inputs.to_vec();
        content.push(&self.token);
        generate_sha1_signature(&content)
    }

    /// 加密给定的数据结构体。加密后的字符串为BASE64编码后的数据。
    pub fn encrypt(&self, input: &Source) -> String {
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
        engine::general_purpose::STANDARD.encode(cipher_bytes)
    }

    /// 解密BASE64编码的加密数据。解密后的数据为Source类型。
    pub fn decrypt(&self, encoded: &str) -> Result<Source, CryptoError> {
        // Base64解码
        let cipher_bytes = engine::general_purpose::STANDARD.decode(encoded)?;
        // AES解密
        let block = Decryptor::<Aes256>::new(&self.key.into(), &self.nonce.into())
            .decrypt_padded_vec_mut::<NoPadding>(&cipher_bytes)
            .map_err(|e| CryptoError::AesDecryption(e.to_string()))?;
        // 获取填充长度与消息长度
        let Some(padding_size) = block.last().copied() else {
            return Err(CryptoError::WecomDecode(
                "Failed to get padding size, empty block".to_string(),
            ));
        };
        let Ok(msg_len_bytes): Result<[u8; 4], _> = block[16..20].try_into() else {
            return Err(CryptoError::WecomDecode("Invalid message size".to_string()));
        };
        // 提取消息
        let msg_len = u32::from_be_bytes(msg_len_bytes) as usize;
        let text = String::from_utf8(block[20..20 + msg_len].to_vec())?;
        let receive_id =
            String::from_utf8(block[20 + msg_len..block.len() - padding_size as usize].to_vec())?;
        Ok(Source { text, receive_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signature() {
        let token = "a";
        let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
        let agent = Agent::new(token, key);
        assert_eq!(
            agent.generate_signature(&["0", "c", "b"]),
            "a8addbc99f8b3f51d2adbceb605d650b9a8940e2",
        );
    }

    #[test]
    fn test_mod_signature() {
        let token = "a";
        assert_eq!(
            super::generate_sha1_signature(&[token, "0", "c", "b"]),
            "a8addbc99f8b3f51d2adbceb605d650b9a8940e2",
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let token = "a";
        let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
        let agent = Agent::new(token, key);
        let source = Source {
            text: "abcd".to_string(),
            receive_id: "xyz".to_string(),
        };
        let enc = agent.encrypt(&source);
        let dec = agent.decrypt(enc.as_str()).unwrap();
        assert_eq!(source, dec);
    }
}
