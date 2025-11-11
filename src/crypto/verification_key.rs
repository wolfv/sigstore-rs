//
// Copyright 2021 The Sigstore Authors.
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

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD_ENGINE};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    ED25519,
};
use x509_cert::{der::{Encode, referenced::OwnedToRef}, spki::SubjectPublicKeyInfoOwned};

use super::{
    Signature, SigningScheme,
    signing_key::{KeyPair, SigStoreSigner},
};

use crate::errors::*;

#[cfg(feature = "cosign")]
use crate::cosign::constants::ED25519 as ED25519_OID;

/// A key that can be used to verify signatures.
///
/// Currently the following key formats are supported:
///
///   * RSA keys, using PSS padding and SHA-256 as the digest algorithm
///   * RSA keys, using PSS padding and SHA-384 as the digest algorithm
///   * RSA keys, using PSS padding and SHA-512 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-256 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-384 as the digest algorithm
///   * RSA keys, using PKCS1 padding and SHA-512 as the digest algorithm
///   * Ed25519 keys, and SHA-512 as the digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-256 curve and SHA-256 as digest algorithm
///   * ECDSA keys, ASN.1 DER-encoded, using the P-384 curve and SHA-384 as digest algorithm
#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CosignVerificationKey {
    RSA_PSS_SHA256(Vec<u8>),
    RSA_PSS_SHA384(Vec<u8>),
    RSA_PSS_SHA512(Vec<u8>),
    RSA_PKCS1_SHA256(Vec<u8>),
    RSA_PKCS1_SHA384(Vec<u8>),
    RSA_PKCS1_SHA512(Vec<u8>),
    ECDSA_P256_SHA256_ASN1(Vec<u8>),
    ECDSA_P384_SHA384_ASN1(Vec<u8>),
    ED25519(Vec<u8>),
}

/// Attempts to convert a [x509 Subject Public Key Info](x509_cert::spki::SubjectPublicKeyInfo) object into
/// a `CosignVerificationKey` one.
///
/// Currently can convert only the following types of keys:
///   * ECDSA P-256: assumes the SHA-256 digest algorithm is used
///   * ECDSA P-384: assumes the SHA-384 digest algorithm is used
///   * RSA: assumes PKCS1 padding is used
impl TryFrom<&SubjectPublicKeyInfoOwned> for CosignVerificationKey {
    type Error = SigstoreError;

    fn try_from(subject_pub_key_info: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let algorithm = subject_pub_key_info.algorithm.oid;
        let public_key_der = &subject_pub_key_info.subject_public_key;
        match algorithm {
            ID_EC_PUBLIC_KEY => {
                match public_key_der.raw_bytes().len() {
                    65 => Ok(CosignVerificationKey::ECDSA_P256_SHA256_ASN1(
                        public_key_der.raw_bytes().to_vec()
                    )),
                    97 => Ok(CosignVerificationKey::ECDSA_P384_SHA384_ASN1(
                        public_key_der.raw_bytes().to_vec()
                    )),
                    _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                        "EC with size {} is not supported",
                        // asn.1 encode caused different length
                        (public_key_der.raw_bytes().len() - 1) * 4
                    ))),
                }
            }
            RSA_ENCRYPTION => {
                // Extract the full SPKI DER encoding for RSA keys
                let spki_der = subject_pub_key_info.to_der()
                    .map_err(|e| SigstoreError::PKCS8SpkiError(format!(
                        "Failed to encode SPKI to DER: {}", e
                    )))?;
                Ok(CosignVerificationKey::RSA_PKCS1_SHA256(spki_der))
            }
            #[cfg(feature = "cosign")]
            ED25519_OID => {
                Ok(CosignVerificationKey::ED25519(
                    public_key_der.raw_bytes().to_vec()
                ))
            }
            _ => Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(format!(
                "Key with algorithm OID {algorithm} is not supported"
            ))),
        }
    }
}

impl CosignVerificationKey {
    /// Builds a [`CosignVerificationKey`] from DER-encoded data. The methods takes care
    /// of extracting the SubjectPublicKeyInfo from the DER-encoded data.
    pub fn from_der(der_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        Ok(match signing_scheme {
            SigningScheme::RSA_PSS_SHA256(_) => {
                CosignVerificationKey::RSA_PSS_SHA256(der_data.to_vec())
            }
            SigningScheme::RSA_PSS_SHA384(_) => {
                CosignVerificationKey::RSA_PSS_SHA384(der_data.to_vec())
            }
            SigningScheme::RSA_PSS_SHA512(_) => {
                CosignVerificationKey::RSA_PSS_SHA512(der_data.to_vec())
            }
            SigningScheme::RSA_PKCS1_SHA256(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA256(der_data.to_vec())
            }
            SigningScheme::RSA_PKCS1_SHA384(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA384(der_data.to_vec())
            }
            SigningScheme::RSA_PKCS1_SHA512(_) => {
                CosignVerificationKey::RSA_PKCS1_SHA512(der_data.to_vec())
            }
            SigningScheme::ECDSA_P256_SHA256_ASN1 => {
                CosignVerificationKey::ECDSA_P256_SHA256_ASN1(der_data.to_vec())
            }
            SigningScheme::ECDSA_P384_SHA384_ASN1 => {
                CosignVerificationKey::ECDSA_P384_SHA384_ASN1(der_data.to_vec())
            }
            SigningScheme::ED25519 => {
                CosignVerificationKey::ED25519(der_data.to_vec())
            }
        })
    }

    /// Builds a [`CosignVerificationKey`] from DER-encoded public key data. This function will
    /// set the verification algorithm due to the public key type, s.t.
    /// * `RSA public key`: `RSA_PKCS1_SHA256`
    /// * `EC public key with P-256 curve`: `ECDSA_P256_SHA256_ASN1`
    /// * `EC public key with P-384 curve`: `ECDSA_P384_SHA384_ASN1`
    /// * `Ed25519 public key`: `Ed25519`
    pub fn try_from_der(der_data: &[u8]) -> Result<Self> {
        // Try to parse as SPKI and determine the key type
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::der::Decode;

        if let Ok(spki) = SubjectPublicKeyInfoOwned::from_der(der_data) {
            let algorithm = spki.algorithm.oid;
            let public_key = &spki.subject_public_key;

            match algorithm {
                ID_EC_PUBLIC_KEY => {
                    match public_key.raw_bytes().len() {
                        65 => Ok(Self::ECDSA_P256_SHA256_ASN1(der_data.to_vec())),
                        97 => Ok(Self::ECDSA_P384_SHA384_ASN1(der_data.to_vec())),
                        _ => Err(SigstoreError::InvalidKeyFormat {
                            error: "Unsupported EC key size".to_string(),
                        }),
                    }
                }
                RSA_ENCRYPTION => Ok(Self::RSA_PKCS1_SHA256(der_data.to_vec())),
                #[cfg(feature = "cosign")]
                ED25519_OID => Ok(Self::ED25519(der_data.to_vec())),
                _ => Err(SigstoreError::InvalidKeyFormat {
                    error: "Failed to parse the public key.".to_string(),
                }),
            }
        } else {
            Err(SigstoreError::InvalidKeyFormat {
                error: "Failed to parse the public key.".to_string(),
            })
        }
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded data. The methods takes care
    /// of decoding the PEM-encoded data and then extracting the SubjectPublicKeyInfo
    /// from the DER-encoded bytes.
    pub fn from_pem(pem_data: &[u8], signing_scheme: &SigningScheme) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::from_der(key_pem.contents(), signing_scheme)
    }

    /// Builds a [`CosignVerificationKey`] from PEM-encoded public key data. This function will
    /// set the verification algorithm due to the public key type, s.t.
    /// * `RSA public key`: `RSA_PKCS1_SHA256`
    /// * `EC public key with P-256 curve`: `ECDSA_P256_SHA256_ASN1`
    /// * `EC public key with P-384 curve`: `ECDSA_P384_SHA384_ASN1`
    /// * `Ed25519 public key`: `Ed25519`
    pub fn try_from_pem(pem_data: &[u8]) -> Result<Self> {
        let key_pem = pem::parse(pem_data)?;
        Self::try_from_der(key_pem.contents())
    }

    /// Builds a `CosignVerificationKey` from [`SigStoreSigner`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`SigStoreSigner`]'s public key.
    pub fn from_sigstore_signer(signer: &SigStoreSigner) -> Result<Self> {
        signer.to_verification_key()
    }

    /// Builds a `CosignVerificationKey` from [`KeyPair`]. The methods will derive
    /// a `CosignVerificationKey` from the given [`KeyPair`]'s public key.
    pub fn from_key_pair(signer: &dyn KeyPair, signing_scheme: &SigningScheme) -> Result<Self> {
        signer.to_verification_key(signing_scheme)
    }

    /// Verify the signature provided has been actually generated by the given key
    /// when signing the provided message.
    pub fn verify_signature(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => BASE64_STD_ENGINE.decode(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA384(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA512(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA384(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA512(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(key) => {
                let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(key) => {
                let public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ED25519(key) => {
                let public_key = UnparsedPublicKey::new(&ED25519, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
        }
    }

    /// Verify the signature provided has been actually generated by the given key
    /// when signing the provided prehashed message.
    pub(crate) fn verify_prehash(&self, signature: Signature, msg: &[u8]) -> Result<()> {
        // Note: aws-lc-rs doesn't have explicit prehash verification APIs like RustCrypto.
        // For RSA, we can still verify the prehash by using the standard verify function
        // since the signature verification process inherently handles prehashed data.
        // For ECDSA, prehash verification is not directly supported in aws-lc-rs,
        // so we'll need to return an error for those cases.

        let sig = match signature {
            Signature::Raw(data) => data.to_owned(),
            Signature::Base64Encoded(data) => BASE64_STD_ENGINE.decode(data)?,
        };

        match self {
            CosignVerificationKey::RSA_PSS_SHA256(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA384(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PSS_SHA512(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA256(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA384(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::RSA_PKCS1_SHA512(key) => {
                let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, key);
                public_key
                    .verify(msg, &sig)
                    .map_err(|_| SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(_) => {
                Err(SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(_) => {
                Err(SigstoreError::PublicKeyVerificationError)
            }
            CosignVerificationKey::ED25519(_) => {
                Err(SigstoreError::PublicKeyVerificationError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    use super::*;
    use crate::crypto::tests::*;

    #[test]
    fn verify_signature_success() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let outcome = verification_key.verify_signature(signature, msg.as_bytes());
        assert!(outcome.is_ok());
    }

    #[test]
    fn verify_signature_failure_because_wrong_msg() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = "hello world";

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::PublicKeyVerificationError);
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_signature_failure_because_wrong_signature() {
        let signature = Signature::Base64Encoded(b"this is a signature");
        let verification_key =
            CosignVerificationKey::from_pem(PUBLIC_KEY.as_bytes(), &SigningScheme::default())
                .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::Base64DecodeError(_));
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_signature_failure_because_wrong_verification_key() {
        let signature = Signature::Base64Encoded(b"MEUCIQD6q/COgzOyW0YH1Dk+CCYSt4uAhm3FDHUwvPI55zwnlwIgE0ZK58ZOWpZw8YVmBapJhBqCfdPekIknimuO0xH8Jh8=");

        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJP9cqpUQsn2ggmJniWGjHdlsHzD
JsB89BPhZYch0U0hKANx5TY+ncrm0s8bfJxxHoenAEFhwhuXeb4PqIrtoQ==
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::default(),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry-testing.svc.lan/busybox"},"image":{"docker-manifest-digest":"sha256:f3cfc9d0dbf931d3db4685ec659b7ac68e2a578219da4aae65427886e649b06b"},"type":"cosign container image signature"},"optional":null}"#;

        let err = verification_key
            .verify_signature(signature, msg.as_bytes())
            .expect_err("Was expecting an error");
        let found = matches!(err, SigstoreError::PublicKeyVerificationError);
        assert!(found, "Didn't get expected error, got {:?} instead", err);
    }

    #[test]
    fn verify_rsa_signature() {
        let signature = Signature::Base64Encoded(b"umasnfYJyLbYPjiq1wIy086Ns+CrgiMoQUSGqPqlUmtWsY0hbngJ73hPfJFrppviPKdBeuUiiwgKagBKIXLEXjwxQp4eE3szwqkKoAnR/lByb7ahLgVQ4MB6xDQaHD53MYtj7aOvd4O7FqJltVVjEn7nM/Du2tL5y3jf6lD7VfHZE8uRocRlyppt8SfTc5L12mVlZ0YlfKYkd334A4y/reCy3Yws0j356Wj7GLScMU5uR11Y2y41rSyYm5uXhTerwNFXsRcPMAmenMarCdCmt4Lf4wpcJBCU172xiK+rIhbMgkLjjA772+auSYf1E8CySVah5CD0Td5YC3y8vIIYaA==");

        let verification_key = CosignVerificationKey::from_pem(
            r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvM/dHoi6nSy7hbKHLYUr
Xy6Bv35JbdoIzny5vSFiRXApr0KS56U8PugdGmh+vd7H8YNlx2YOJxzv02Blsrcm
WDZcXjE3Xpsi/IHFfRZLOdwwR+u8MNFxwRUVzxyIzKGtbREVVfXPfb2Xc6FL5/tE
vQtUKuR6XdzSaav2RnV5IybCB09s0Np0AUbdi5EfSe4INuqgY+VFYLjvM5onbAQL
N3bFLS4Quk66Dhv93Zi6NwopwL1F07UPC5uadkyePStP3PA0OAOemj9vZADOWx5a
dsGCKISs8iphNC5mDVoLy8Ry49Ms3eQXRjVQOMco3YNf8AhsIdxDNBVN8VTDKVkE
DwIDAQAB
-----END PUBLIC KEY-----"#
                .as_bytes(),
            &SigningScheme::RSA_PKCS1_SHA256(0),
        )
        .expect("Cannot create CosignVerificationKey");
        let msg = r#"{"critical":{"identity":{"docker-reference":"registry.suse.com/suse/sle-micro/5.0/toolbox"},"image":{"docker-manifest-digest":"sha256:356631f7603526a0af827741f5fe005acf19b7ef7705a34241a91c2d47a6db5e"},"type":"cosign container image signature"},"optional":{"creator":"OBS"}}"#;

        assert!(
            verification_key
                .verify_signature(signature, msg.as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn convert_ecdsa_p256_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let (private_key, public_key) = generate_ecdsa_p256_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ECDSA_P256_SHA256_ASN1(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_ecdsa_p384_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let (private_key, public_key) = generate_ecdsa_p384_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ECDSA_P384_SHA384_ASN1(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_rsa_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let (private_key, public_key) = generate_rsa_keypair(2048);
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::RSA_PKCS1_SHA256(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_ed25519_subject_public_key_to_cosign_verification_key() -> anyhow::Result<()> {
        let (private_key, public_key) = generate_ed25519_keypair();
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let cosign_verification_key =
            CosignVerificationKey::try_from(&spki).expect("conversion failed");

        assert!(matches!(
            cosign_verification_key,
            CosignVerificationKey::ED25519(_)
        ));
        Ok(())
    }

    #[test]
    fn convert_unsupported_curve_subject_public_key_to_cosign_verification_key()
    -> anyhow::Result<()> {
        let (private_key, public_key) = generate_dsa_keypair(2048);
        let issued_cert_generation_options = CertGenerationOptions {
            private_key,
            public_key,
            ..Default::default()
        };

        let ca_data = generate_certificate(None, CertGenerationOptions::default())?;

        let issued_cert = generate_certificate(Some(&ca_data), issued_cert_generation_options)?;
        let issued_cert_pem = issued_cert.cert.to_pem()?;
        let pem = pem::parse(issued_cert_pem)?;
        let cert = Certificate::from_der(pem.contents())?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        let err = CosignVerificationKey::try_from(&spki);
        assert!(matches!(
            err,
            Err(SigstoreError::PublicKeyUnsupportedAlgorithmError(_))
        ));

        Ok(())
    }
}
