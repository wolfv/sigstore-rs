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

//! # ECDSA Keys using aws-lc-rs
//!
//! This module provides ECDSA key pair generation, signing, and verification
//! using the aws-lc-rs cryptographic library instead of RustCrypto.
//!
//! Supported curves:
//! * P-256 (secp256r1)
//! * P-384 (secp384r1)

use std::marker::PhantomData;

use aws_lc_rs::signature::{
    EcdsaKeyPair,
    KeyPair as AwsKeyPair,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
};
use aws_lc_rs::rand::SystemRandom;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        SigningScheme,
        signing_key::{
            COSIGN_PRIVATE_KEY_PEM_LABEL, KeyPair, PRIVATE_KEY_PEM_LABEL,
            SIGSTORE_PRIVATE_KEY_PEM_LABEL, Signer, kdf,
        },
        verification_key::CosignVerificationKey,
    },
    errors::*,
};

use super::ECDSAKeys;

/// Marker trait for ECDSA curves
pub trait EcdsaCurve {
    /// Returns the signing algorithm for this curve
    fn signing_algorithm() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm;

    /// Returns the curve name
    fn curve_name() -> &'static str;
}

/// Marker type for P-256 curve
#[derive(Debug, Clone, Copy)]
pub struct P256;

impl EcdsaCurve for P256 {
    fn signing_algorithm() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
        &ECDSA_P256_SHA256_ASN1_SIGNING
    }

    fn curve_name() -> &'static str {
        "P-256"
    }
}

/// Marker type for P-384 curve
#[derive(Debug, Clone, Copy)]
pub struct P384;

impl EcdsaCurve for P384 {
    fn signing_algorithm() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
        &ECDSA_P384_SHA384_ASN1_SIGNING
    }

    fn curve_name() -> &'static str {
        "P-384"
    }
}

/// Generic ECDSA key pair using aws-lc-rs
#[derive(Debug)]
pub struct EcdsaKeys<C: EcdsaCurve> {
    // Store the key in PKCS#8 DER format for serialization
    pkcs8_der: Zeroizing<Vec<u8>>,
    // Store the public key separately
    public_key_der: Vec<u8>,
    _marker: PhantomData<C>,
}

impl<C: EcdsaCurve> Clone for EcdsaKeys<C> {
    fn clone(&self) -> Self {
        Self {
            pkcs8_der: self.pkcs8_der.clone(),
            public_key_der: self.public_key_der.clone(),
            _marker: PhantomData,
        }
    }
}

impl<C: EcdsaCurve> EcdsaKeys<C> {
    /// Create a new `EcdsaKeys` Object with a randomly generated key pair
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8_der = EcdsaKeyPair::generate_pkcs8(C::signing_algorithm(), &rng)
            .map_err(|e| SigstoreError::PKCS8Error(format!("ECDSA key generation failed: {}", e)))?
            .as_ref()
            .to_vec();

        // Parse the key to get the public key
        let key_pair = EcdsaKeyPair::from_pkcs8(C::signing_algorithm(), &pkcs8_der)
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to parse generated key: {}", e)))?;
        let public_key_der = key_pair.public_key().as_ref().to_vec();

        Ok(EcdsaKeys {
            pkcs8_der: Zeroizing::new(pkcs8_der),
            public_key_der,
            _marker: PhantomData,
        })
    }

    /// Builds an `EcdsaKeys` from encrypted pkcs8 PEM-encoded private key.
    pub fn from_encrypted_pem(private_key: &[u8], password: &[u8]) -> Result<Self> {
        let key = pem::parse(private_key)?;
        match key.tag() {
            COSIGN_PRIVATE_KEY_PEM_LABEL | SIGSTORE_PRIVATE_KEY_PEM_LABEL => {
                let der = kdf::decrypt(key.contents(), password)?;
                Self::from_der(&der)
            }
            PRIVATE_KEY_PEM_LABEL if password.is_empty() => Self::from_pem(private_key),
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

    /// Builds an `EcdsaKeys` from a pkcs8 PEM-encoded private key.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        let pem_str = std::str::from_utf8(pem_data)?;
        let parsed_pem = pem::parse(pem_str)?;

        match parsed_pem.tag() {
            PRIVATE_KEY_PEM_LABEL => Self::from_der(parsed_pem.contents()),
            tag => Err(SigstoreError::PrivateKeyDecryptError(format!(
                "Unsupported pem tag {tag}"
            ))),
        }
    }

    /// Builds an `EcdsaKeys` from a pkcs8 DER-encoded private key.
    pub fn from_der(private_key: &[u8]) -> Result<Self> {
        // Verify the key can be parsed
        let key_pair = EcdsaKeyPair::from_pkcs8(C::signing_algorithm(), private_key)
            .map_err(|e| SigstoreError::PKCS8Error(format!(
                "Convert from pkcs8 der to ecdsa private key failed: {}", e
            )))?;

        let public_key_der = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            pkcs8_der: Zeroizing::new(private_key.to_vec()),
            public_key_der,
            _marker: PhantomData,
        })
    }

    /// Convert the [`EcdsaKeys`] into [`ECDSAKeys`].
    pub fn to_wrapped_ecdsa_keys(&self) -> Result<ECDSAKeys> {
        ECDSAKeys::from_der(&self.pkcs8_der[..])
    }

    /// Get a reference to the PKCS#8 DER-encoded private key
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }
}

impl EcdsaKeys<P256> {
    /// Create a [`SigStoreSigner`] from this P256 key
    pub fn to_sigstore_signer(&self) -> Result<crate::crypto::signing_key::SigStoreSigner> {
        use crate::crypto::signing_key::{EcdsaSigner, SigStoreSigner};
        use sha2::Sha256;
        Ok(SigStoreSigner::ECDSA_P256_SHA256_ASN1(
            EcdsaSigner::<P256, Sha256>::from_ecdsa_keys(self)?
        ))
    }
}

impl EcdsaKeys<P384> {
    /// Create a [`SigStoreSigner`] from this P384 key
    pub fn to_sigstore_signer(&self) -> Result<crate::crypto::signing_key::SigStoreSigner> {
        use crate::crypto::signing_key::{EcdsaSigner, SigStoreSigner};
        use sha2::Sha384;
        Ok(SigStoreSigner::ECDSA_P384_SHA384_ASN1(
            EcdsaSigner::<P384, Sha384>::from_ecdsa_keys(self)?
        ))
    }
}

impl<C: EcdsaCurve> KeyPair for EcdsaKeys<C> {
    /// Return the public key in PEM-encoded SPKI format.
    fn public_key_to_pem(&self) -> Result<String> {
        let pem = pem::Pem::new("PUBLIC KEY", self.public_key_der.clone());
        Ok(pem::encode(&pem))
    }

    /// Return the private key in pkcs8 PEM-encoded format.
    fn private_key_to_pem(&self) -> Result<Zeroizing<String>> {
        let pem = pem::Pem::new(PRIVATE_KEY_PEM_LABEL, self.pkcs8_der.to_vec());
        Ok(Zeroizing::new(pem::encode(&pem)))
    }

    /// Return the public key in DER SPKI format.
    fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.public_key_der.clone())
    }

    /// Return the private key in pkcs8 DER format.
    fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.pkcs8_der.clone())
    }

    /// Return the encrypted private key in PEM-encoded format.
    fn private_key_to_encrypted_pem(&self, password: &[u8]) -> Result<Zeroizing<String>> {
        let pem = pem::Pem::new(
            SIGSTORE_PRIVATE_KEY_PEM_LABEL,
            kdf::encrypt(&self.pkcs8_der, password)?,
        );
        Ok(Zeroizing::new(pem::encode(&pem)))
    }

    /// Derive the relative [`CosignVerificationKey`].
    fn to_verification_key(&self, signing_scheme: &SigningScheme) -> Result<CosignVerificationKey> {
        let pem = self.public_key_to_pem()?;
        CosignVerificationKey::from_pem(pem.as_bytes(), signing_scheme)
    }
}

/// `EcdsaSigner` is used to generate ECDSA signatures using aws-lc-rs.
#[derive(Clone, Debug)]
pub struct EcdsaSigner<C: EcdsaCurve, D> {
    ecdsa_keys: EcdsaKeys<C>,
    _digest_marker: PhantomData<D>,
}

impl<C: EcdsaCurve, D> EcdsaSigner<C, D> {
    /// Create a new `EcdsaSigner` from the given `EcdsaKeys`
    pub fn from_ecdsa_keys(ecdsa_keys: &EcdsaKeys<C>) -> Result<Self> {
        Ok(Self {
            ecdsa_keys: (*ecdsa_keys).clone(),
            _digest_marker: PhantomData,
        })
    }

    /// Return the ref to the keypair inside the signer
    pub fn ecdsa_keys(&self) -> &EcdsaKeys<C> {
        &self.ecdsa_keys
    }
}

impl<C: EcdsaCurve, D> Signer for EcdsaSigner<C, D> {
    /// Sign the given message and return an ASN.1 DER-encoded signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            C::signing_algorithm(),
            &self.ecdsa_keys.pkcs8_der,
        )
        .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to load key: {}", e)))?;

        let signature = key_pair
            .sign(&rng, msg)
            .map_err(|e| SigstoreError::PKCS8Error(format!("Signing failed: {}", e)))?;

        Ok(signature.as_ref().to_vec())
    }

    /// Return the ref to the keypair inside the signer
    fn key_pair(&self) -> &dyn KeyPair {
        &self.ecdsa_keys
    }
}

#[cfg(test)]
mod tests {
    use super::{EcdsaKeys, EcdsaSigner, P256};
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
    fn ecdsa_generate_and_sign() {
        let key = EcdsaKeys::<P256>::new().expect("Failed to create ECDSA key");
        let signer = EcdsaSigner::<P256, sha2::Sha256>::from_ecdsa_keys(&key)
            .expect("Failed to create signer");

        let sig = signer.sign(MESSAGE.as_bytes()).expect("Failed to sign");
        assert!(!sig.is_empty());
    }

    #[test]
    fn ecdsa_to_and_from_pem() {
        let key = EcdsaKeys::<P256>::new().expect("create ecdsa keys failed");
        let pem = key.private_key_to_pem().expect("export to PEM failed");
        let key2 = EcdsaKeys::<P256>::from_pem(pem.as_bytes()).expect("import from PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn ecdsa_to_and_from_der() {
        let key = EcdsaKeys::<P256>::new().expect("create ecdsa keys failed");
        let der = key.private_key_to_der().expect("export to DER failed");
        let key2 = EcdsaKeys::<P256>::from_der(&der).expect("import from DER failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn ecdsa_to_and_from_encrypted_pem() {
        let key = EcdsaKeys::<P256>::new().expect("create ecdsa keys failed");
        let enc_pem = key.private_key_to_encrypted_pem(PASSWORD)
            .expect("export to encrypted PEM failed");
        let key2 = EcdsaKeys::<P256>::from_encrypted_pem(enc_pem.as_bytes(), PASSWORD)
            .expect("import from encrypted PEM failed");

        // Verify they're the same by comparing public keys
        let pub1 = key.public_key_to_der().unwrap();
        let pub2 = key2.public_key_to_der().unwrap();
        assert_eq!(pub1, pub2);
    }
}
