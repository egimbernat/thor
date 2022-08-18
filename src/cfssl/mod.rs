use anyhow::Error;
use chrono::{DateTime, Utc};
use openssl::error::ErrorStack;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{fs, str};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{error, info};

const CA_FROM_REMOTE: &str = "remote";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Definition {
    pub request: Request,
    pub profiles: Profiles,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    #[serde(rename = "CN")]
    pub cn: String,
    pub hosts: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profiles {
    pub paths: Paths,
    pub cfssl: Cfssl,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paths {
    #[serde(rename = "private_key")]
    pub private_key: String,
    pub certificate: String,
    #[serde(default)]
    pub bundle: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cfssl {
    pub profile: String,
    pub remote: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    pub serial_number: String,
    pub authority_key_identifier: String,
    pub status: String,
    pub common_name: String,
}

impl Cfssl {
    fn get_remote(&self) -> String {
        std::env::var("CFSSL_ADDRESS").unwrap_or_else(|_| self.remote.clone())
    }
}

#[derive(Default)]
pub struct Pki {
    pub certificate: String,
    pub private_key: String,
    pub ca_certificate: String,
    pub bundle: String,

    pub cert_path: String,
    pub key_path: String,
    pub bundle_path: String,
    crl: BTreeMap<String, String>,
}

impl Pki {
    pub async fn new_with_crl_refresh(
        definition: &String,
        bundle: bool,
        crl_url: &str,
        crl_update_interval: u64,
    ) -> Result<Arc<Mutex<Pki>>, Error> {
        let mut pki = Pki {
            crl: BTreeMap::new(),
            ..Default::default()
        };

        pki.fill_object(definition, bundle).await?;

        let pki = Arc::new(Mutex::new(pki));

        let pki_c = pki.clone();
        let crl_url_c = crl_url.to_string();
        tokio::spawn(async move {
            loop {
                let pki = pki_c.clone();
                match Pki::get_crl(crl_url_c.clone()).await {
                    Ok(certs) => {
                        let mut p_lock = pki.lock().unwrap();
                        p_lock.update_crl(certs);
                        info!("CRL downloaded and installed correctly");
                        drop(p_lock);
                    }
                    Err(err) => error!("Error occurred getting and installing CRL: {}", err),
                }

                tokio::time::sleep(Duration::from_secs(crl_update_interval)).await;
            }
        });

        Ok(pki)
    }
    #[allow(dead_code)]
    pub async fn fill_object_with_replace(
        &mut self,
        definition: String,
        id: &str,
        bundle: bool,
    ) -> Result<(), Error> {
        let data = fs::read_to_string(definition)?.replace("{proxy_id}", id);

        self.fill_object_from_str(&*data, bundle).await
    }
    pub async fn fill_object(&mut self, definition: &String, bundle: bool) -> Result<(), Error> {
        let data = fs::read_to_string(definition)?;

        self.fill_object_from_str(&*data, bundle).await
    }
    pub async fn fill_object_from_str(
        &mut self,
        definition: &str,
        bundle: bool,
    ) -> Result<(), Error> {
        let obj: Definition = serde_json::from_str(&*definition)?;

        self.cert_path = obj.profiles.paths.certificate.clone();
        self.key_path = obj.profiles.paths.private_key.clone();

        let cert_p = Path::new(&obj.profiles.paths.certificate);
        let key_p = Path::new(&obj.profiles.paths.private_key);
        let bundle_p = Path::new(&obj.profiles.paths.bundle);

        if !cert_p.exists() || !key_p.exists() {
            self.renew_cert(obj, bundle).await?;
        } else {
            let cert = fs::read_to_string(cert_p.to_str().unwrap())?.replace("\\n", "\n");
            let cert_req = json!({ "certificate": cert });
            let response = reqwest::Client::new()
                .post(format!(
                    "{}/api/v1/cfssl/certinfo",
                    obj.profiles.cfssl.get_remote()
                ))
                .json(&cert_req)
                .send()
                .await?;

            let res: Value = response.json().await?;

            let not_after = res["result"]["not_after"].as_str().unwrap();
            let after = DateTime::parse_from_rfc3339(not_after)?;

            if after < Utc::now() {
                self.renew_cert(obj, bundle).await?;
            } else {
                let key = fs::read_to_string(key_p.to_str().unwrap())?;

                self.certificate = cert;
                self.private_key = key;

                let ca = Pki::load_ca_certificate(CA_FROM_REMOTE.to_string()).await?;
                self.ca_certificate = String::from_utf8(ca)?;

                if bundle {
                    let bundle = fs::read_to_string(bundle_p.to_str().unwrap())?;
                    self.bundle = bundle;
                    self.bundle_path = obj.profiles.paths.bundle;
                }
            }
        }

        Ok(())
    }

    async fn renew_cert(&mut self, obj: Definition, bundle: bool) -> Result<(), Error> {
        let cert_req = json!({
            "request": obj.request,
            "profile": obj.profiles.cfssl.profile
        });
        let response = reqwest::Client::new()
            .post(format!(
                "{}/api/v1/cfssl/newcert",
                obj.profiles.cfssl.get_remote()
            ))
            .json(&cert_req)
            .send()
            .await?;

        let res: Value = response.json().await?;

        self.certificate = res["result"]["certificate"].as_str().unwrap().to_string();
        let temp_key = res["result"]["private_key"].as_str().unwrap().to_string();

        let temp_key = self.convert_key(temp_key)?;
        self.private_key = str::from_utf8(&*temp_key)?.to_string();

        fs::write(&obj.profiles.paths.certificate, &self.certificate)?;
        fs::write(&obj.profiles.paths.private_key, &self.private_key)?;

        if bundle {
            let bundle = self
                .get_cert_chain_bundle(CA_FROM_REMOTE.to_string())
                .await?;
            self.bundle = bundle;

            fs::write(&obj.profiles.paths.bundle, &self.bundle)?;
            self.bundle_path = obj.profiles.paths.bundle;
        }

        self.cert_path = obj.profiles.paths.certificate;
        self.key_path = obj.profiles.paths.private_key;

        Ok(())
    }
    pub fn convert_key(&self, key: String) -> Result<Vec<u8>, ErrorStack> {
        let private_key = openssl::pkey::PKey::private_key_from_pem(key.as_ref()).unwrap();
        private_key.private_key_to_pem_pkcs8()
    }

    pub async fn get_cert_chain_bundle(&mut self, path: String) -> Result<String, Error> {
        let ca = Pki::load_ca_certificate(path).await?;
        self.ca_certificate = String::from_utf8(ca)?;
        Ok(format!("{}{}", self.certificate, self.ca_certificate))
    }

    pub async fn load_ca_certificate(path: String) -> Result<Vec<u8>, Error> {
        return if path == CA_FROM_REMOTE {
            let addr = std::env::var("CFSSL_ADDRESS")
                .expect("You must specify CFSSL_ADDRESS to use remote CA");

            let req = json!({"label": "primary"});
            let response = reqwest::Client::new()
                .post(format!("{}/api/v1/cfssl/info", addr))
                .json(&req)
                .send()
                .await?;

            let res: Value = response.json().await?;

            let ca: Vec<u8> = res["result"]["certificate"]
                .as_str()
                .unwrap()
                .to_string()
                .as_bytes()
                .to_vec();

            Ok(ca)
        } else {
            let pem = tokio::fs::read(&*path).await?;
            Ok(pem)
        };
    }
    pub(crate) fn contains_key(&self, key: &String) -> bool {
        self.crl.contains_key(key)
    }
    pub async fn get_crl(url: String) -> Result<Vec<Certificate>, Error> {
        let response = reqwest::Client::new()
            .get(format!("{}/certificates/revoked", url))
            .send()
            .await?;

        let res: Vec<Certificate> = response.json().await?;

        Ok(res)
    }

    fn update_crl(&mut self, certs: Vec<Certificate>) {
        certs.iter().for_each(|c| {
            self.crl
                .insert(c.serial_number.clone(), c.common_name.clone());
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::cfssl::Pki;
    use chrono::DateTime;
    use std::io::BufReader;

    #[tokio::main]
    #[test]
    #[ignore]
    async fn parse() {
        let dummy = r#"
        {
  "request": {
    "CN": "thor",
    "hosts": [
      "thor",
      "127.0.0.1",
      "192.168.100.25"
    ]
  },
  "profiles": {
    "paths": {
      "private_key": "server.key",
      "certificate": "server.pem",
      "bundle": "cert-chain.pem"
    },
    "cfssl": {
      "profile": "server",
      "remote": "http://127.0.0.1:8888"
    }
  },
  "roots": [
    {
      "type": "system"
    }
  ],
  "client_roots": [
  ]
}"#;
        std::env::set_var("CFSSL_ADDRESS", "http://localhost:8888");
        let mut pki = Pki::default();
        pki.fill_object_from_str(dummy, true).await.unwrap();
    }

    #[test]
    pub fn parse_time() {
        DateTime::parse_from_rfc3339("2022-11-16T07:57:00Z").unwrap();
    }

    #[tokio::main]
    #[test]
    #[ignore]
    async fn test_pkcs8() {
        let data = tokio::fs::read("server.key").await.unwrap();
        let mut reader = BufReader::new(&data[..]);

        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut reader).unwrap();

        assert_eq!(pkcs8.len(), 1);
    }

    #[tokio::main]
    #[test]
    #[ignore]
    async fn test_remote_ca() {
        std::env::set_var("CFSSL_ADDRESS", "http://localhost:8888");
        let data = Pki::load_ca_certificate("remote".to_string()).await;

        println!("{:?}", data.unwrap())
    }
}
