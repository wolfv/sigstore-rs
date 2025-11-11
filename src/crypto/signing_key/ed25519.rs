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

//! # Ed25519 Keys using aws-lc-rs
//!
//! This module provides Ed25519 key pair generation, signing, and verification
//! using the aws-lc-rs cryptographic library instead of RustCrypto.

use aws_lc_rs::signature::{
    Ed25519KeyPair, KeyPair as AwsKeyPair,
};
use aws_lc_rs::rand::SystemRandom;
use zeroize::Zeroizing;
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::{
    crypto::{SigningScheme, verification_key::CosignVerificationKey},
    errors::*,
};

use super::{
    COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL, SIGSTORE_PRIVATE_KEY_PEM_LABEL,
    SigStoreSigner, Signer, kdf,
};

#[derive(Debug, Clone)]
pub struct Ed25519Keys {
    // Store the key in PKCS#8 DER format for serialization
    pkcs8_der: Zeroizing<Vec<u8>>,
    // Store the public key separately
    public_key: Vec<u8>,
}

impl Ed25519Keys {
    /// Create a new `Ed25519Keys` Object with a randomly generated key pair
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_der = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| SigstoreError::Ed25519PKCS8Error(format!("Ed25519 key generation failed: {}", e)))?
            .as_ref()
            .to_vec();

        // Extract the SPKI-encoded public key from the PKCS#8 private key
        let pkcs8_info = pkcs8::PrivateKeyInfo::from_der(&pkcs8_der)
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to parse PKCS#8: {}", e)))?;
        let public_key_bytes = pkcs8_info.public_key
            .ok_or_else(|| SigstoreError::PKCS8Error("No public key in PKCS#8".to_string()))?;

        // Construct SPKI from algorithm and public key
        use x509_cert::der::referenced::OwnedToRef;
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: pkcs8_info.algorithm.oid,
            parameters: pkcs8_info.algorithm.parameters.map(|p| p.to_owned().into()),
        };
        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: x509_cert::der::asn1::BitString::from_bytes(public_key_bytes)
                .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to create BitString: {}", e)))?,
        };
        let public_key = spki.to_der()
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to encode SPKI: {}", e)))?;

        Ok(Ed25519Keys {
            pkcs8_der: Zeroizing::new(pkcs8_der),
            public_key,
        })
    }

    /// Create a new `Ed25519Keys` Object from given `Ed25519Keys` Object.
    pub fn from_ed25519key(key: &Ed25519Keys) -> Result<Self> {
        Self::from_der(&key.pkcs8_der)
    }

    /// Builds an `Ed25519Keys` from encrypted pkcs8 PEM-encoded private key.
    pub fn from_encrypted_pem(encrypted_pem: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(encrypted_pem)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                Self::from_der(&der)
            }
            PRIVATE_KEY_PEM_LABEL if password.is_empty() => Self::from_pem(encrypted_pem),
            PRIVATE_KEY_PEM_LABEL if !password.is_empty() => {
                Err(SigstoreError::PrivateKeyDecryptError(
                    "Unencrypted private key but password provided".into(),
                ))
            }
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds an `Ed25519Keys` from a pkcs8 PEM-encoded private key.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem)?;
        let parsed_pem = pem::parse(pem_str)?;

        match parsed_pem.tag() {
            PRIVATE_KEY_PEM_LABEL => Self::from_der(parsed_pem.contents()),
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds an `Ed25519Keys` from a pkcs8 DER-encoded private key.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        // Parse the key to get the public key directly from aws-lc-rs
        let key_pair = Ed25519KeyPair::from_pkcs8(der_bytes)
            .map_err(|e| SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ed25519 private key failed: {}", e
            )))?;
        let public_key_bytes = key_pair.public_key().as_ref();

        // Extract algorithm info from PKCS#8
        let pkcs8_info = pkcs8::PrivateKeyInfo::from_der(der_bytes)
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to parse PKCS#8: {}", e)))?;

        // Construct SPKI from algorithm and public key
        use x509_cert::der::referenced::OwnedToRef;
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: pkcs8_info.algorithm.oid,
            parameters: pkcs8_info.algorithm.parameters.map(|p| p.to_owned().into()),
        };
        let spki = SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: x509_cert::der::asn1::BitString::from_bytes(public_key_bytes)
                .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to create BitString: {}", e)))?,
        };
        let public_key = spki.to_der()
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to encode SPKI: {}", e)))?;

        Ok(Self {
            pkcs8_der: Zeroizing::new(der_bytes.to_vec()),
            public_key,
        })
    }

    /// `to_sigstore_signer` will create the [`SigStoreSigner`] using
    /// this ed25519 private key.
    pub fn to_sigstore_signer(&self) -> Result<SigStoreSigner> {
        Ok(SigStoreSigner::ED25519(Ed25519Signer::from_ed25519_keys(
            self,
        )?))
    }
}

impl KeyPair for Ed25519Keys {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        let pem = pem::Pem::new("PUBLIC KEY", self.public_key.clone());
        Ok(pem::encode(&pem))
    }

    /// Return the public key in DER SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.public_key.clone())
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
    fn to_verification_key(
        &self,
        _signature_digest_algorithm: &SigningScheme,
    ) -> Result<CosignVerificationKey> {
        let der = self.public_key_to_der()?;
        CosignVerificationKey::from_der(&der, &SigningScheme::ED25519)
    }
}

#[derive(Debug)]
pub struct Ed25519Signer {
    key_pair: Ed25519Keys,
}

impl Ed25519Signer {
    pub fn from_ed25519_keys(ed25519_keys: &Ed25519Keys) -> Result<Self> {
        Ok(Self {
            key_pair: ed25519_keys.clone(),
        })
    }

    /// Return the ref to the keypair inside the signer
    pub fn ed25519_keys(&self) -> &Ed25519Keys {
        &self.key_pair
    }
}

impl Signer for Ed25519Signer {
    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.key_pair
    }

    /// Sign the given message using Ed25519
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&self.key_pair.pkcs8_der)
            .map_err(|e| SigstoreError::Ed25519PKCS8Error(format!("Failed to load key: {}", e)))?;

        let signature = key_pair.sign(msg);
        Ok(signature.as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Keys, Ed25519Signer};
    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{KeyPair, Signer},
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
    const EMPTY_PASSWORD: &[u8] = b"";

    #[test]
    fn ed25519_generate_and_sign() {
        let key = Ed25519Keys::new().expect("Failed to create Ed25519 key");
        let signer = Ed25519Signer::from_ed25519_keys(&key).expect("Failed to create signer");

        let sig = signer.sign(MESSAGE.as_bytes()).expect("Failed to sign");
        assert!(!sig.is_empty());
    }

    #[test]
    fn ed25519_to_and_from_pem() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed");
        let pem = key.private_key_to_pem().expect("export to PEM failed");
        let key2 = Ed25519Keys::from_pem(pem.as_bytes()).expect("import from PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn ed25519_to_and_from_der() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed");
        let der = key.private_key_to_der().expect("export to DER failed");
        let key2 = Ed25519Keys::from_der(&der).expect("import from DER failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn ed25519_to_and_from_encrypted_pem() {
        let key = Ed25519Keys::new().expect("create ed25519 keys failed");
        let enc_pem = key.private_key_to_encrypted_pem(PASSWORD)
            .expect("export to encrypted PEM failed");
        let key2 = Ed25519Keys::from_encrypted_pem(enc_pem.as_bytes(), PASSWORD)
            .expect("import from encrypted PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }
}
