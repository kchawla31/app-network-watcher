use crate::{Error, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct CertificateAuthority {
    pub dir: PathBuf,
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub fingerprint: String,
}

impl CertificateAuthority {
    pub fn load_or_create(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            return Self::from_pem(dir, cert_pem, key_pem);
        }
        Self::generate(dir)
    }

    pub fn generate(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let key_pair = KeyPair::generate().map_err(|err| Error::Message(err.to_string()))?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "App Network Watcher CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "App Network Watcher");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let cert = params
            .self_signed(&key_pair)
            .map_err(|err| Error::Message(err.to_string()))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        write_private(&dir.join("ca.key"), key_pem.as_bytes())?;
        fs::write(dir.join("ca.pem"), &cert_pem)?;
        fs::write(dir.join("ca.cer"), cert.der())?;
        Self::from_pem(dir, cert_pem, key_pem)
    }

    fn from_pem(dir: PathBuf, cert_pem: String, key_pem: String) -> Result<Self> {
        let der = pem_to_der(&cert_pem)?;
        let fingerprint = fingerprint_sha256(&der);
        fs::write(dir.join("ca.cer"), &der)?;
        Ok(Self {
            dir,
            cert_pem,
            key_pem,
            cert_der: der,
            fingerprint,
        })
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    pub fn cer_path(&self) -> PathBuf {
        self.dir.join("ca.cer")
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("ca.key")
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut collecting = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            collecting = true;
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break;
        }
        if collecting {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() {
        return Err(Error::Message("CA PEM did not contain a certificate.".into()));
    }
    base64_decode(&b64)
}

fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
    }
    let _ = SystemTime::now().duration_since(UNIX_EPOCH);
    Ok(())
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn val(byte: u8) -> Result<u8> {
        match byte {
            b'A'..=b'Z' => Ok(byte - b'A'),
            b'a'..=b'z' => Ok(byte - b'a' + 26),
            b'0'..=b'9' => Ok(byte - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(Error::Message("invalid base64 in certificate".into())),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = *bytes.get(i + 1).unwrap_or(&b'=');
        let b2 = *bytes.get(i + 2).unwrap_or(&b'=');
        let b3 = *bytes.get(i + 3).unwrap_or(&b'=');
        let n = (u32::from(val(b0)?) << 18)
            | (u32::from(if b1 == b'=' { 0 } else { val(b1)? }) << 12)
            | (u32::from(if b2 == b'=' { 0 } else { val(b2)? }) << 6)
            | u32::from(if b3 == b'=' { 0 } else { val(b3)? });
        out.push((n >> 16) as u8);
        if b2 != b'=' {
            out.push((n >> 8) as u8);
        }
        if b3 != b'=' {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_reloads_with_the_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let created = CertificateAuthority::generate(dir.path()).unwrap();
        assert!(created.fingerprint.len() > 20);
        assert!(created.cert_path().exists());
        let loaded = CertificateAuthority::load_or_create(dir.path()).unwrap();
        assert_eq!(created.fingerprint, loaded.fingerprint);
        assert!(loaded.cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
