# wecom-crypto
`wecom-crypto`提供了企业微信API数据的加解密功能。其实现完全遵循官方文档中的规定。

## 使用方法
```rust
use wecom_crypto::{CryptoAgent, CryptoSource};

let key = "cGCVnNJRgRu6wDgo7gxG2diBovGnRQq1Tqy4Rm4V4qF";
let agent = CryptoAgent::new(key);
let source = CryptoSource {
    text: "hello world!".to_string(),
    receive_id: "wandering-ai".to_string(),
};
let enc = agent.encrypt(&source);
let dec = agent.decrypt(enc.as_str()).unwrap();
assert_eq!(source, dec);
```
