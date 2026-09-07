//! Certificate pinning for provider endpoints.
//!
//! Proxmox serves a certificate signed by its own per-cluster CA, and we connect
//! by IP, so ordinary PKI validation cannot succeed. The alternative most people
//! reach for is disabling verification entirely — but an API token that can
//! create VMs and attach GPUs travels over this connection. Pinning the exact
//! certificate is both stronger than hostname validation and simpler than
//! distributing the cluster CA.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct PinnedCert {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedCert {
    /// Accepts the colon-separated uppercase form that `openssl x509 -fingerprint`
    /// prints, so what is in the config is what an operator can verify by hand.
    pub fn new(fingerprint: &str, provider: Arc<CryptoProvider>) -> anyhow::Result<Self> {
        let hex: String = fingerprint.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 64 {
            anyhow::bail!("expected a SHA-256 fingerprint (64 hex digits), got {}", hex.len());
        }
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
        }
        Ok(Self { fingerprint: bytes, provider })
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        // Constant-time comparison is unnecessary here (the expected value is
        // public), but an exact match is: no chain, no hostname, no expiry
        // fallback. Either it is the certificate we pinned or the handshake dies.
        if actual == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "certificate fingerprint mismatch: server presented {}",
                actual.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client(fingerprint: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20));

    let Some(fp) = fingerprint else {
        anyhow::bail!(
            "no tlsFingerprintSha256 configured. Read it with:\n  \
             openssl s_client -connect <host>:8006 </dev/null 2>/dev/null | \
             openssl x509 -noout -fingerprint -sha256"
        );
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedCert::new(fp, provider.clone())?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(builder.use_preconfigured_tls(tls).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_separated_and_bare_fingerprints() {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let colons = "65:D0:EB:78:43:4D:A1:69:F7:A7:2D:A4:70:B0:DD:F7:8A:EB:A3:B4:35:78:D4:AF:C1:CD:6D:D5:13:D6:BD:82";
        let bare = colons.replace(':', "");
        let a = PinnedCert::new(colons, p.clone()).unwrap();
        let b = PinnedCert::new(&bare, p.clone()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.fingerprint[0], 0x65);
        assert_eq!(a.fingerprint[31], 0x82);
        assert!(PinnedCert::new("65:D0", p).is_err(), "short fingerprints must be rejected");
    }
}
