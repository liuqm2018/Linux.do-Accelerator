use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::config::AppConfig;
use crate::platform::sync_user_ownership;

#[derive(Debug, Clone)]
pub struct CertificateBundle {
    pub ca_cert_path: PathBuf,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
}

const CA_VALIDITY_DAYS: i64 = 365;
const SERVER_VALIDITY_DAYS: i64 = 365;

pub fn ensure_bundle(config: &AppConfig, root: &Path) -> Result<CertificateBundle> {
    generate_bundle(config, root)
}

/// Returns the root CA certificate as DER bytes, for installing/trusting on a
/// device (iOS wants DER for `.mobileconfig` / trust settings). Ensures the
/// bundle exists first, then reads the PEM CA back and re-encodes to DER.
pub fn export_ca_der(config: &AppConfig, root: &Path) -> Result<Vec<u8>> {
    let bundle = ensure_bundle(config, root)?;
    let pem = fs::read_to_string(&bundle.ca_cert_path)
        .with_context(|| format!("failed to read {}", bundle.ca_cert_path.display()))?;
    let der = pem_to_der(&pem).context("failed to decode CA PEM to DER")?;
    Ok(der)
}

/// Minimal PEM (single CERTIFICATE block) → DER decoder, no extra deps.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut base64 = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            break;
        }
        if in_body {
            base64.push_str(trimmed);
        }
    }
    if base64.is_empty() {
        bail!("no PEM body found");
    }
    base64_decode(&base64)
}

/// Standard base64 decoder (RFC 4648), tolerating whitespace and padding.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c).ok_or_else(|| anyhow!("invalid base64 character"))?;
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

pub fn load_bundle(root: &Path) -> Result<CertificateBundle> {
    let bundle = bundle_paths(root);
    if !bundle_all_exist(&bundle) {
        bail!(
            "certificate files not found in {}; run setup first",
            root.display()
        );
    }
    Ok(bundle)
}

fn bundle_paths(root: &Path) -> CertificateBundle {
    CertificateBundle {
        ca_cert_path: root.join("linuxdo-accelerator-root-ca.crt"),
        server_cert_path: root.join("linuxdo-accelerator-server.crt"),
        server_key_path: root.join("linuxdo-accelerator-server.key"),
    }
}

fn generate_bundle(config: &AppConfig, root: &Path) -> Result<CertificateBundle> {
    let cert_dir = root.to_path_buf();
    fs::create_dir_all(&cert_dir)
        .with_context(|| format!("failed to create {}", cert_dir.display()))?;

    let bundle = bundle_paths(&cert_dir);

    let domains_hash_path = cert_dir.join("linuxdo-accelerator-domains.sha256");
    let current_hash = domains_hash(&config.certificate_domains);

    if bundle_all_exist(&bundle) {
        if let Ok(saved_hash) = fs::read_to_string(&domains_hash_path) {
            if saved_hash.trim() == current_hash {
                return Ok(bundle);
            }
        }
    }

    remove_existing_bundle_files(&bundle)?;

    let ca_cert = generate_ca(config, &bundle)?;
    generate_server_cert(config, &bundle, &ca_cert)?;

    fs::write(&domains_hash_path, &current_hash)
        .with_context(|| format!("failed to write {}", domains_hash_path.display()))?;

    Ok(bundle)
}

fn bundle_all_exist(bundle: &CertificateBundle) -> bool {
    bundle.ca_cert_path.exists() && bundle.server_cert_path.exists() && bundle.server_key_path.exists()
}

fn domains_hash(domains: &[String]) -> String {
    let mut hasher = DefaultHasher::new();
    domains.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn generate_ca(config: &AppConfig, bundle: &CertificateBundle) -> Result<Certificate> {
    let (ca_not_before, ca_not_after) = validity_window(CA_VALIDITY_DAYS)?;
    let mut ca_params = CertificateParams::default();
    ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    ca_params.not_before = ca_not_before;
    ca_params.not_after = ca_not_after;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, config.ca_common_name.clone());
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let ca_cert = Certificate::from_params(ca_params).context("failed to generate root CA")?;

    fs::write(
        &bundle.ca_cert_path,
        ca_cert
            .serialize_pem()
            .context("failed to serialize root CA")?,
    )
    .with_context(|| format!("failed to write {}", bundle.ca_cert_path.display()))?;
    sync_user_ownership(&bundle.ca_cert_path)?;

    Ok(ca_cert)
}

fn generate_server_cert(
    config: &AppConfig,
    bundle: &CertificateBundle,
    ca_cert: &Certificate,
) -> Result<()> {
    let (server_not_before, server_not_after) = validity_window(SERVER_VALIDITY_DAYS)?;
    let mut server_params = CertificateParams::new(config.certificate_domains.clone());
    server_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    server_params.not_before = server_not_before;
    server_params.not_after = server_not_after;
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, config.server_common_name.clone());
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.use_authority_key_identifier_extension = true;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let server_cert =
        Certificate::from_params(server_params).context("failed to generate server cert")?;

    fs::write(
        &bundle.server_cert_path,
        server_cert
            .serialize_pem_with_signer(ca_cert)
            .context("failed to sign server cert")?,
    )
    .with_context(|| format!("failed to write {}", bundle.server_cert_path.display()))?;
    fs::write(
        &bundle.server_key_path,
        server_cert.serialize_private_key_pem(),
    )
    .with_context(|| format!("failed to write {}", bundle.server_key_path.display()))?;
    sync_user_ownership(&bundle.server_cert_path)?;
    sync_user_ownership(&bundle.server_key_path)?;

    Ok(())
}

fn remove_existing_bundle_files(bundle: &CertificateBundle) -> Result<()> {
    for path in [
        &bundle.ca_cert_path,
        &bundle.server_cert_path,
        &bundle.server_key_path,
    ] {
        match fs::remove_file(path) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to remove {}", path.display()));
            }
        }
    }
    Ok(())
}

fn validity_window(valid_days: i64) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let now = OffsetDateTime::now_utc();
    let not_before = now
        .checked_sub(Duration::days(1))
        .ok_or_else(|| anyhow!("failed to compute certificate not_before"))?;
    let not_after = now
        .checked_add(Duration::days(valid_days))
        .ok_or_else(|| anyhow!("failed to compute certificate not_after"))?;
    Ok((not_before, not_after))
}
