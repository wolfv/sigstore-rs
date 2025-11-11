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

//! # RSA Signer using aws-lc-rs
//!
//! RSA Signer supports the following padding schemes:
//! * `PSS`
//! * `PKCS#1 v1.5`
//!
//! And the following digest algorithms:
//! * `Sha256`
//! * `Sha384`
//! * `Sha512`

use aws_lc_rs::signature::{
    RsaKeyPair,
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
};
use aws_lc_rs::rand::SystemRandom;

use self::keypair::RSAKeys;

use crate::{crypto::CosignVerificationKey, errors::*};

use super::{KeyPair, Signer};

pub mod keypair;

pub const DEFAULT_KEY_SIZE: usize = 2048;

/// Different digest algorithms used in RSA-based signing algorithm.
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Different padding schemes used in RSA-based signing algorithm.
/// * `PSS`: Probabilistic Signature Scheme, more secure than `PKCS1v15`.
/// * `PKCS1v15`: also known as simply PKCS1, is a simple padding
///   scheme developed for use with RSA keys.
pub enum PaddingScheme {
    PSS,
    PKCS1v15,
}

/// RSA signing scheme families:
/// * `PKCS1v15`: PKCS#1 1.5 padding for RSA signatures.
/// * `PSS`: RSA PSS padding for RSA signatures.
///
/// Both schemes support the following digest algorithms:
/// * `Sha256`
/// * `Sha384`
/// * `Sha512`
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum RSASigner {
    RSA_PSS_SHA256(RSAKeys),
    RSA_PSS_SHA384(RSAKeys),
    RSA_PSS_SHA512(RSAKeys),
    RSA_PKCS1_SHA256(RSAKeys),
    RSA_PKCS1_SHA384(RSAKeys),
    RSA_PKCS1_SHA512(RSAKeys),
}

/// Helper to generate match arms
macro_rules! iter_on_rsa {
    ($domain: ident, $match_item: expr, $key: ident, $func: expr) => {
        match $match_item {
            $domain::RSA_PSS_SHA256($key) => $func,
            $domain::RSA_PSS_SHA384($key) => $func,
            $domain::RSA_PSS_SHA512($key) => $func,
            $domain::RSA_PKCS1_SHA256($key) => $func,
            $domain::RSA_PKCS1_SHA384($key) => $func,
            $domain::RSA_PKCS1_SHA512($key) => $func,
        }
    };
}

impl RSASigner {
    pub fn from_rsa_keys(
        rsa_keys: &RSAKeys,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Self {
        match padding_scheme {
            PaddingScheme::PSS => match digest_algorithm {
                DigestAlgorithm::Sha256 => RSASigner::RSA_PSS_SHA256(rsa_keys.clone()),
                DigestAlgorithm::Sha384 => RSASigner::RSA_PSS_SHA384(rsa_keys.clone()),
                DigestAlgorithm::Sha512 => RSASigner::RSA_PSS_SHA512(rsa_keys.clone()),
            },
            PaddingScheme::PKCS1v15 => match digest_algorithm {
                DigestAlgorithm::Sha256 => RSASigner::RSA_PKCS1_SHA256(rsa_keys.clone()),
                DigestAlgorithm::Sha384 => RSASigner::RSA_PKCS1_SHA384(rsa_keys.clone()),
                DigestAlgorithm::Sha512 => RSASigner::RSA_PKCS1_SHA512(rsa_keys.clone()),
            },
        }
    }

    pub fn from_rsa_keys_enum(
        rsa_keys: &RSAKeys,
        digest_algorithm: DigestAlgorithm,
        padding_scheme: PaddingScheme,
    ) -> Result<crate::crypto::signing_key::SigStoreSigner> {
        use crate::crypto::signing_key::SigStoreSigner;

        Ok(match padding_scheme {
            PaddingScheme::PSS => match digest_algorithm {
                DigestAlgorithm::Sha256 => {
                    SigStoreSigner::RSA_PSS_SHA256(RSASigner::RSA_PSS_SHA256(rsa_keys.clone()))
                }
                DigestAlgorithm::Sha384 => {
                    SigStoreSigner::RSA_PSS_SHA384(RSASigner::RSA_PSS_SHA384(rsa_keys.clone()))
                }
                DigestAlgorithm::Sha512 => {
                    SigStoreSigner::RSA_PSS_SHA512(RSASigner::RSA_PSS_SHA512(rsa_keys.clone()))
                }
            },
            PaddingScheme::PKCS1v15 => match digest_algorithm {
                DigestAlgorithm::Sha256 => SigStoreSigner::RSA_PKCS1_SHA256(
                    RSASigner::RSA_PKCS1_SHA256(rsa_keys.clone()),
                ),
                DigestAlgorithm::Sha384 => SigStoreSigner::RSA_PKCS1_SHA384(
                    RSASigner::RSA_PKCS1_SHA384(rsa_keys.clone()),
                ),
                DigestAlgorithm::Sha512 => SigStoreSigner::RSA_PKCS1_SHA512(
                    RSASigner::RSA_PKCS1_SHA512(rsa_keys.clone()),
                ),
            },
        })
    }

    /// Return the ref to the [`RSAKeys`] inside the RSASigner
    pub fn rsa_keys(&self) -> &RSAKeys {
        iter_on_rsa!(RSASigner, self, key, key)
    }

    /// Return the related [`CosignVerificationKey`] of this RSASigner
    pub fn to_verification_key(&self) -> Result<CosignVerificationKey> {
        use crate::crypto::SigningScheme;

        let signing_scheme = match self {
            RSASigner::RSA_PSS_SHA256(_) => SigningScheme::RSA_PSS_SHA256(0),
            RSASigner::RSA_PSS_SHA384(_) => SigningScheme::RSA_PSS_SHA384(0),
            RSASigner::RSA_PSS_SHA512(_) => SigningScheme::RSA_PSS_SHA512(0),
            RSASigner::RSA_PKCS1_SHA256(_) => SigningScheme::RSA_PKCS1_SHA256(0),
            RSASigner::RSA_PKCS1_SHA384(_) => SigningScheme::RSA_PKCS1_SHA384(0),
            RSASigner::RSA_PKCS1_SHA512(_) => SigningScheme::RSA_PKCS1_SHA512(0),
        };

        iter_on_rsa!(RSASigner, self, key, key.to_verification_key(&signing_scheme))
    }

}

impl Signer for RSASigner {
    /// `sign` will sign the given data, and return the signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::signature::KeyPair as _;
        let rng = SystemRandom::new();
        let key = self.rsa_keys();

        let key_pair = RsaKeyPair::from_pkcs8(key.pkcs8_der())
            .map_err(|e| SigstoreError::PKCS8Error(format!("Failed to load RSA key: {}", e)))?;

        let mut signature = vec![0u8; key_pair.public_key().modulus_len()];

        // Call the appropriate signing algorithm
        let result = match self {
            RSASigner::RSA_PSS_SHA256(_) => key_pair.sign(&RSA_PSS_SHA256, &rng, msg, &mut signature),
            RSASigner::RSA_PSS_SHA384(_) => key_pair.sign(&RSA_PSS_SHA384, &rng, msg, &mut signature),
            RSASigner::RSA_PSS_SHA512(_) => key_pair.sign(&RSA_PSS_SHA512, &rng, msg, &mut signature),
            RSASigner::RSA_PKCS1_SHA256(_) => key_pair.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut signature),
            RSASigner::RSA_PKCS1_SHA384(_) => key_pair.sign(&RSA_PKCS1_SHA384, &rng, msg, &mut signature),
            RSASigner::RSA_PKCS1_SHA512(_) => key_pair.sign(&RSA_PKCS1_SHA512, &rng, msg, &mut signature),
        };

        result.map_err(|e| SigstoreError::PKCS8Error(format!("RSA signing failed: {}", e)))?;
        Ok(signature)
    }

    /// Return the ref to the [`KeyPair`] trait object inside the RSASigner
    fn key_pair(&self) -> &dyn KeyPair {
        iter_on_rsa!(RSASigner, self, key, key)
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_KEY_SIZE, DigestAlgorithm, PaddingScheme, RSASigner, keypair::RSAKeys};
    use crate::crypto::{
        Signature, SigningScheme,
        signing_key::{KeyPair, Signer},
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

    #[test]
    fn rsa_pss_sha256() {
        let rsa_keys = RSAKeys::new(DEFAULT_KEY_SIZE).expect("RSA keys generated failed.");
        let signer = RSASigner::from_rsa_keys(&rsa_keys, DigestAlgorithm::Sha256, PaddingScheme::PSS);
        let sig = signer.sign(MESSAGE.as_bytes()).expect("sign failed.");
        let vk = rsa_keys
            .to_verification_key(&SigningScheme::RSA_PSS_SHA256(0))
            .expect("derive CosignVerificationKey failed.");
        let signature = Signature::Raw(&sig);
        vk.verify_signature(signature, MESSAGE.as_bytes())
            .expect("can not verify the signature.");
    }

    #[test]
    fn rsa_pkcs1_sha256() {
        let rsa_keys = RSAKeys::new(DEFAULT_KEY_SIZE).expect("RSA keys generated failed.");
        let signer = RSASigner::from_rsa_keys(&rsa_keys, DigestAlgorithm::Sha256, PaddingScheme::PKCS1v15);
        let sig = signer.sign(MESSAGE.as_bytes()).expect("sign failed.");
        let vk = rsa_keys
            .to_verification_key(&SigningScheme::RSA_PKCS1_SHA256(0))
            .expect("derive CosignVerificationKey failed.");
        let signature = Signature::Raw(&sig);
        vk.verify_signature(signature, MESSAGE.as_bytes())
            .expect("can not verify the signature.");
    }
}
