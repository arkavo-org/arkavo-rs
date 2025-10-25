//
// parse_certificates.rs : Defines functions necessary for certificate bundle input parsing
//
// Copyright © 2025 Apple Inc. All rights reserved.
//

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use base64::engine::general_purpose;
use base64::Engine;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sha::{sha1, sha256};
use openssl::x509::X509;
use x509_parser::prelude::*;

use crate::base::base_constants::{FPSCertificateStructs, FPS_CERT_PATH, FPS_SDK_MAJOR_VERSION, FPS_SDK_MINOR_VERSION, FPS_SDK_VERSION_CERTIFICATE_OID};
use crate::base::structures::base_fps_structures::{Base, CertificateList, CertificateBundle, LegacyCertificate};
use crate::base::structures::base_server_structures::{CertData, FPSServerSPCContainer};
use crate::base::Utils::FPSServerUtils::readBigEndianU16;
use crate::returnErrorStatus;
use crate::fpsLogError;
use crate::validate::{Result, FPSStatus};
use crate::Extension;

pub static CERT_MAP: OnceLock<HashMap<String, CertData>> = OnceLock::new();
//used to convert between SHA256 and SHA1
pub static CERT_CONVERT_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

impl Base {
    pub fn readCertificates() -> Result<()> {
        let fileLocation = std::env::var(FPS_CERT_PATH).unwrap_or(Extension::getDefaultCertPath());
        let parentPath = Path::new(&fileLocation).parent().unwrap_or(Path::new("")).to_str().unwrap_or_default();

        let fileReader = match std::fs::File::open(&fileLocation) {
            Ok(r) => r,
            Err(e) => {
                fpsLogError!(FPSStatus::paramErr, "Failed to read certificate file ({}): {}", fileLocation, e);
                returnErrorStatus!(FPSStatus::paramErr);
            }
        };

        let certList: CertificateList = match serde_jsonrc::from_reader(fileReader) {
            Ok(r) => r,
            Err(e) => {
                fpsLogError!(FPSStatus::paramErr, "Failed to parse certificate file ({}): {}", fileLocation, e);
                returnErrorStatus!(FPSStatus::paramErr);
            }
        };

        let mut certMap: HashMap<String, CertData> = HashMap::default();
        let mut conversionMap: HashMap<String, String> = HashMap::default();
        for certificate in certList.certificates.iter() {
            match certificate {
                FPSCertificateStructs::certBundle(bundle) => {
                    generateCertBundleHashes(parentPath, &mut certMap, &mut conversionMap, bundle)?;
                },
                FPSCertificateStructs::legacyCert(legacyCert) => {
                    generateLegacyCertHash(parentPath, &mut certMap, &mut conversionMap, legacyCert)?;
                }
            };
        }

        CERT_MAP.get_or_init(|| {certMap});
        CERT_CONVERT_MAP.get_or_init(|| {conversionMap});
        Ok(())
    }

    pub fn matchSha1withSha256(spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        let cert_map = match CERT_CONVERT_MAP.get() {
            Some(s) => s,
            None => {
                fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to get SHA256 conversion hash map");
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }
        };
        let certHash = hex::encode(&spcContainer.certificateHash256);
        let sha1CertHash = cert_map.get(&certHash);

        if let Some(hash) = sha1CertHash {
            spcContainer.certificateHash = match hex::decode(hash) {
                Ok(r) => r,
                Err(e) => {
                    fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to decode certificate hash: {}", e);
                    returnErrorStatus!(FPSStatus::invalidCertificateErr);
                }
            };
        }
        else {
            fpsLogError!(FPSStatus::invalidCertificateErr, "No matching cert hash found");
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
        
        Ok(())
    }
}

fn getFullPath(parentPath: &str, fileName: &String) -> String {
    if fileName.starts_with('/') {
        // fileName is an absolute path. Use it directly.
        return fileName.clone()
    } else {
        // fileName is a relative path. Prepend parentPath.
        return parentPath.to_string() + "/" + fileName
    }
}

fn generateCertBundleHashes(
    parentPath: &str,
    certMap: &mut HashMap<String, CertData>,
    certConversion: &mut HashMap<String, String>,
    bundle: &CertificateBundle
) -> Result<()> {

    //Certificate parsing
    let mut bundleFile = match std::fs::File::open(getFullPath(parentPath, &bundle.certBundle)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening certificate bundle file: {} {}", getFullPath(parentPath, &bundle.certBundle), e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };


    let mut bundleBytes: Vec<u8> = vec![];
    if let Err(e) = bundleFile.read_to_end(&mut bundleBytes) {
        fpsLogError!(FPSStatus::paramErr, "Error reading certificate bundle from file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }


    let (cert1024, cert2048) = parseCertificateBundle(&bundleBytes)?;

    //Only check the certificate version for 2048 certificates, 1024 certificates will not have
    //these version values
    checkCertificateVersion(&cert2048)?;

    //Private key parsing
    let mut pkey1024File = match std::fs::File::open(getFullPath(parentPath, &bundle.pkey1024)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening 1024 bit private key file: {}", e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };

    let mut pkey1024Bytes: Vec<u8> = vec![];
    if let Err(e) = pkey1024File.read_to_end(&mut pkey1024Bytes) {
        fpsLogError!(FPSStatus::paramErr, "Error reading 1024 bit private key file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }
    let pkey1024 = parsePrivateKey(&pkey1024Bytes)?;

    validatePrivateKey(&cert1024, &pkey1024)?;

    let mut pkey2048File = match std::fs::File::open(getFullPath(parentPath, &bundle.pkey2048)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening 2048 bit private key file: {}", e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };

    let mut pkey2048Bytes: Vec<u8> = vec![];
    if let Err(e) = pkey2048File.read_to_end(&mut pkey2048Bytes) {
        fpsLogError!(FPSStatus::paramErr, "Error reading 2048 bit private key file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }
    let pkey2048 = parsePrivateKey(&pkey2048Bytes)?;

    validatePrivateKey(&cert2048, &pkey2048)?;

    //Provisioning data parsing
    let mut provisioningDataFile = match std::fs::File::open(getFullPath(parentPath, &bundle.provisioningData)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening 2048 bit private key file: {}", e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };

    let mut provisioningData: Vec<u8> = vec![];
    if let Err(e) = provisioningDataFile.read_to_end(&mut provisioningData) {
        fpsLogError!(FPSStatus::paramErr, "Error reading provisioning data file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }

    //Hash of 1024 certificate only
    let certBytes = match cert1024.to_der() {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Error converting certificate to der format: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };
    let sha = sha1(&certBytes);
    let sha2 = sha256(&certBytes);
    let shaString = hex::encode(sha);
    let sha256String = hex::encode(sha2);
    certMap.insert(shaString.clone(), CertData {certificate: cert1024.clone(), privateKey: pkey1024.clone(), provisioningData: provisioningData.clone()});
    certConversion.insert(sha256String, shaString);

    //Hash of 2048 certificate only
    let certBytes = match cert2048.to_der() {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Error converting certificate to der format: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    let sha = sha1(&certBytes);
    let sha2 = sha256(&certBytes);
    let shaString = hex::encode(sha);
    let sha256String = hex::encode(sha2);
    certMap.insert(shaString.clone(), CertData {certificate: cert2048, privateKey: pkey2048, provisioningData: provisioningData.clone()});
    certConversion.insert(sha256String, shaString);

    //Hash of entire bundle (1024 certificate)
    let bundleSha = sha1(&bundleBytes);
    let bundleSha256 = sha256(&bundleBytes);
    let bundleShaString = hex::encode(bundleSha);
    let bundleSha256String = hex::encode(bundleSha256);
    certMap.insert(bundleShaString.clone(), CertData {certificate: cert1024, privateKey: pkey1024, provisioningData});
    certConversion.insert(bundleSha256String, bundleShaString);


    Ok(())
}


fn generateLegacyCertHash(
    parentPath: &str,
    certMap: &mut HashMap<String, CertData>,
    certConversion: &mut HashMap<String, String>,
    legacyCert: &LegacyCertificate
) -> Result<()> {

    //Certificate parsing
    let mut certFile = match std::fs::File::open(getFullPath(parentPath, &legacyCert.legacyCert)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening legacy certificate file: {}", e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };


    let mut certBytes: Vec<u8> = vec![];
    if let Err(e) = certFile.read_to_end(&mut certBytes) {
        fpsLogError!(FPSStatus::paramErr, "Error reading legacy certificate from file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }

    let certificate = if let Ok(cert) = X509::from_der(&certBytes) {
        cert
    }
    else if let Ok(cert) = X509::from_pem(&certBytes) {
        cert
    }
    else {
        fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to parse legacy certificate");
        returnErrorStatus!(FPSStatus::invalidCertificateErr);
    };


    let tempDerCert = match certificate.to_der() {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to re-encode certificate to der: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };
    let sha = sha1(&tempDerCert);
    let sha2 = sha256(&tempDerCert);
    let shaString = hex::encode(sha);
    let sha256String = hex::encode(sha2);

    //Private key parsing
    let mut pkeyFile = match std::fs::File::open(getFullPath(parentPath, &legacyCert.pkey1024)) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::paramErr, "Error opening 1024 bit private key file: {}", e);
            returnErrorStatus!(FPSStatus::paramErr);
        }
    };

    let mut pkeyBytes: Vec<u8> = vec![];
    if let Err(e) = pkeyFile.read_to_end(&mut pkeyBytes) {
        fpsLogError!(FPSStatus::paramErr, "Error reading 1024 bit private key file: {}", e);
        returnErrorStatus!(FPSStatus::paramErr);
    }
    let privateKey = parsePrivateKey(&pkeyBytes)?;

    //Provisioning data (ASk) parsing
    let provisioningData = if let Ok(data) = hex::decode(&legacyCert.ask) {
        data
    }
    else if let Ok(data) = general_purpose::STANDARD.decode(&legacyCert.ask) {
        data
    }
    else {
            fpsLogError!(FPSStatus::paramErr, "Error decoding legacy cert ASk");
            returnErrorStatus!(FPSStatus::paramErr);
    };

    if provisioningData.len() != 16 {
        fpsLogError!(FPSStatus::paramErr, "ASk is invalid length: {}", provisioningData.len());
        returnErrorStatus!(FPSStatus::paramErr);
    }

    certMap.insert(shaString.clone(), CertData {certificate, privateKey, provisioningData});
    certConversion.insert(sha256String, shaString);
    Ok(())
}

fn parseCertificateBundle(bundleBytes: &Vec<u8>) -> Result<(X509, X509)> {
    let mut bundleOffset = 0;

    let cert1024 = match X509::from_der(&bundleBytes) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to parse 1024 cert from certificate bundle: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    //get length of cert in der format
    bundleOffset += match cert1024.to_der() {
        Ok(r) => r.len(),
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to get 1024 certificate length: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    let cert2048 = match X509::from_der(&bundleBytes[bundleOffset..]) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to parse 2048 certiciate: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    Ok((cert1024, cert2048))
}



fn parsePrivateKey(keyBytes: &[u8]) -> Result<Rsa<Private>> {
    let privateKey = if let Ok(key) = Rsa::private_key_from_der(keyBytes) {
        key
    }
    else if let Ok(key) = Rsa::private_key_from_pem(keyBytes) {
        key
    }
    else {
        fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to parse private key");
        returnErrorStatus!(FPSStatus::invalidCertificateErr);
    };

    Ok(privateKey)
}

fn validatePrivateKey(certificate: &X509, privateKey: &Rsa<Private>) -> Result<()> {
    let certPublicKey = match certificate.public_key() {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to get certificate public key: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    let rsaKey = match certPublicKey.rsa() {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Failed to get rsa key: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };

    if rsaKey.n() == privateKey.n() {
        Ok(())
    }
    else {
        fpsLogError!(FPSStatus::invalidCertificateErr, "private key and public key do not match");
        returnErrorStatus!(FPSStatus::invalidCertificateErr);
    }
}

fn checkCertificateVersion(certificate: &X509) -> Result<()> {
    let der = certificate.to_der().unwrap();
    let (_, cert_extensions) = match X509Certificate::from_der(der.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            fpsLogError!(FPSStatus::invalidCertificateErr, "Unable to read certificate: {}", e);
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    };
    let cert_extensions = cert_extensions.extensions();

    for extension in cert_extensions.into_iter() {
        if extension.oid.to_id_string() == FPS_SDK_VERSION_CERTIFICATE_OID {
            if extension.value.len() != 4 || extension.value[0] != 2 || extension.value[1] != 2 {
                fpsLogError!(FPSStatus::invalidCertificateErr, "Invalid certificate version");
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }

            let sdk_version = readBigEndianU16(extension.value, 2)?;
            let version_major: u32 = ((sdk_version >> 8) & 0x00FF) as u32;
            let version_minor: u32 = (sdk_version & 0x00FF) as u32;

            //Warn when the certificate version is older than the current sdk version
            if version_major < FPS_SDK_MAJOR_VERSION || (version_major == FPS_SDK_MAJOR_VERSION && version_minor < FPS_SDK_MINOR_VERSION) {
               fpsLogError!(FPSStatus::noErr, "Certificate is older version than the current SDK version");
            }

            //Error when the certificate version is newer than the current sdk version
            if version_major > FPS_SDK_MAJOR_VERSION || (version_major == FPS_SDK_MAJOR_VERSION &&  version_minor > FPS_SDK_MINOR_VERSION) {
                fpsLogError!(FPSStatus::invalidCertificateErr, "Certificate is newer than the current SDK version");
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }

            //Once the certificate version is found, no need to keep parsing
            return Ok(());
        }
    }
    //warn when no certificate version is found
    log::warn!("No certificate version found");
    Ok(())
}


