//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # RSA Key Pair using aws-lc-rs
//!
//! This module provides RSA key pair generation and operations
//! using the aws-lc-rs cryptographic library instead of RustCrypto.

use aws_lc_rs::signature::{RsaKeyPair, KeyPair as AwsKeyPair};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::KeySize;
use zeroize::Zeroizing;

use crate::{
    crypto::{CosignVerificationKey, SigStoreSigner, SigningScheme},
    errors::*,
};

use crate::crypto::signing_key::{
    COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL, RSA_PRIVATE_KEY_PEM_LABEL,
    SIGSTORE_PRIVATE_KEY_PEM_LABEL, kdf,
};

use super::{DigestAlgorithm, PaddingScheme, RSASigner};

#[derive(Clone, Debug)]
pub struct RSAKeys {
    // Store the key in PKCS#8 DER format
    pkcs8_der: Zeroizing<Vec<u8>>,
    // Store the public key separately
    public_key_der: Vec<u8>,
}

impl RSAKeys {
    /// Create a new `RSAKeys` Object with a randomly generated key pair.
    pub fn new(bit_size: usize) -> Result<Self> {
        // Convert bit_size to KeySize
        let key_size = match bit_size {
            2048 => KeySize::Rsa2048,
            3072 => KeySize::Rsa3072,
            4096 => KeySize::Rsa4096,
            8192 => KeySize::Rsa8192,
            _ => return Err(SigstoreError::PKCS8Error(format!("Unsupported RSA key size: {}", bit_size))),
        };

        let key_pair = RsaKeyPair::generate(key_size)
            .map_err(|e| SigstoreError::PKCS8Error(format!("RSA key generation failed: {}", e)))?;
        let pkcs8_der = key_pair.as_der()
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to serialize RSA key: {}", e)))?
            .as_ref()
            .to_vec();

        // Parse to get public key
        let key_pair = RsaKeyPair::from_pkcs8(&pkcs8_der)
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to parse generated RSA key: {}", e)))?;
        let public_key_der = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            pkcs8_der: Zeroizing::new(pkcs8_der),
            public_key_der,
        })
    }

    /// Create a new `RSAKeys` Object from given `RSAKeys` Object.
    pub fn from_rsa_privatekey_key(key: &RSAKeys) -> Result<Self> {
        Self::from_der(&key.pkcs8_der)
    }

    /// Builds an `RSAKeys` from encrypted pkcs8 PEM-encoded private key.
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                Self::from_der(&der)
            }
            RSA_PRIVATE_KEY_PEM_LABEL | PRIVATE_KEY_PEM_LABEL if password.is_empty() => {
                Self::from_pem(encrypted_pem)
            }
            RSA_PRIVATE_KEY_PEM_LABEL | PRIVATE_KEY_PEM_LABEL if !password.is_empty() => {
                Err(SigstoreError::PrivateKeyDecryptError(
                    "Unencrypted private key but password provided".into(),
                ))
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds an `RSAKeys` from a pkcs8 PEM-encoded private key.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem)?;
        let parsed_pem = pem::parse(pem_str)?;

        match parsed_pem.tag() {
            PRIVATE_KEY_PEM_LABEL | RSA_PRIVATE_KEY_PEM_LABEL => {
                Self::from_der(parsed_pem.contents())
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds an `RSAKeys` from a pkcs8 DER-encoded private key.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        // Verify the key can be parsed
        let key_pair = RsaKeyPair::from_pkcs8(der_bytes)
            .map_err(|e| SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to rsa private key failed: {}", e
            )))?;

        let public_key_der = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            pkcs8_der: Zeroizing::new(der_bytes.to_vec()),
            public_key_der,
        })
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this rsa key pair.
    pub fn to_sigstore_signer(
        &self,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Result<SigStoreSigner> {
        RSASigner::from_rsa_keys_enum(self, digest_algorithm, padding_scheme)
    }

    /// Get a reference to the PKCS#8 DER-encoded private key
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }
}

impl KeyPair for RSAKeys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        let pem = pem::Pem::new("PUBLIC KEY", self.public_key_der.clone());
        Ok(pem::encode(&pem))
    }

    /// Return the public key in DER SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.public_key_der.clone())
    }

    /// Return the encrypted private key in PEM-encoded format.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        let pem = pem::Pem::new(
            SIGSTORE_PRIVATE_KEY_PEM_LABEL,
            kdf::encrypt(&self.pkcs8_der, password)?,
        );
        Ok(Zeroizing::new(pem::encode(&pem)))
    }

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        let pem = pem::Pem::new(PRIVATE_KEY_PEM_LABEL, self.pkcs8_der.to_vec());
        Ok(Zeroizing::new(pem::encode(&pem)))
    }

    /// Return the private key in pkcs8 DER format.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        let der = self.public_key_to_der()?;
        CosignVerificationKey::from_der(&der, signing_scheme)
    }
}

#[cfg(test)]
mod tests {
    use super::RSAKeys;
    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{
            KeyPair, Signer,
            rsa::{DigestAlgorithm, PaddingScheme, RSASigner},
        },
        verification_key::CosignVerificationKey,
    };

    const MESSAGE: &str = r#"{
        "critical": {
            "identity": {
                "docker-reference": "registry-testing.svc.lan/busybox"
            },
            "image": {
                "docker-manifest-digest": "sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"
            },
            "type": "cosign container image signature"
        },
        "optional": null
    }"#;

    const PASSWORD: &[u8] = b"123";
    const KEY_SIZE: usize = 2048;

    #[test]
    fn rsa_generate_and_sign() {
        let key = RSAKeys::new(KEY_SIZE).expect("Failed to create RSA key");
        let signer = RSASigner::from_rsa_keys(&key, DigestAlgorithm::Sha256, PaddingScheme::PSS);

        let sig = signer.sign(MESSAGE.as_bytes()).expect("Failed to sign");
        assert!(!sig.is_empty());
    }

    #[test]
    fn rsa_to_and_from_pem() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed");
        let pem = key.private_key_to_pem().expect("export to PEM failed");
        let key2 = RSAKeys::from_pem(pem.as_bytes()).expect("import from PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn rsa_to_and_from_der() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed");
        let der = key.private_key_to_der().expect("export to DER failed");
        let key2 = RSAKeys::from_der(&der).expect("import from DER failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn rsa_to_and_from_encrypted_pem() {
        let key = RSAKeys::new(KEY_SIZE).expect("create rsa keys failed");
        let enc_pem = key.private_key_to_encrypted_pem(PASSWORD)
            .expect("export to encrypted PEM failed");
        let key2 = RSAKeys::from_encrypted_pem(enc_pem.as_bytes(), PASSWORD)
            .expect("import from encrypted PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }
}
