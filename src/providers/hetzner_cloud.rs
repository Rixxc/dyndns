// SPDX-FileCopyrightText: 2023 Benedikt Bastin
// SPDX-License-Identifier: AGPL-3.0-or-later

#![deny(clippy::all)]

use std::{
    error::Error,
    fmt::{self},
};

use futures::executor::block_on;
use log::info;
use serde::{Deserialize, Serialize};

use crate::config::{DomainConfig, Zone};

#[derive(Deserialize)]
struct Zones {
    zones: Vec<Zone>,
}

#[derive(PartialEq, Eq, Deserialize, Serialize, strum_macros::Display)]
#[allow(clippy::min_ident_chars)]
pub enum RecordType {
    A,
    AAAA,
    NS,
    MX,
    CNAME,
    RP,
    TXT,
    SOA,
    HINFO,
    SRV,
    DANE,
    TLSA,
    DS,
    CAA,
}

#[derive(Deserialize, Serialize)]
struct RecordValue {
    value: String,
}

#[derive(Deserialize)]
struct RRset {
    name: String,
    #[serde(rename = "type")]
    record_type: RecordType,
    ttl: Option<u64>,
    records: Vec<RecordValue>,
}

impl fmt::Display for RRset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let values: Vec<&str> = self.records.iter().map(|r| r.value.as_str()).collect();
        write!(
            f,
            "{} {} {} {}",
            self.name,
            self.ttl.unwrap_or(0),
            self.record_type,
            values.join(", ")
        )
    }
}

#[derive(Deserialize)]
struct RRsets {
    rrsets: Vec<RRset>,
}

#[derive(Serialize)]
struct SetRecords {
    records: Vec<RecordValue>,
}

#[derive(Default)]
pub struct HetznerCloudProvider {
    client: reqwest::Client,
}

impl HetznerCloudProvider {
    #[must_use]
    pub fn new() -> HetznerCloudProvider {
        let p = HetznerCloudProvider {
            client: reqwest::Client::new(),
        };
        info!("Created new Hetzner Cloud Provider");

        p
    }

    fn auth_header(apitoken: &str) -> String {
        format!("Bearer {apitoken}")
    }

    pub async fn get_zones(&self, apitoken: &str) -> Result<Vec<Zone>, Box<dyn Error>> {
        let response = self
            .client
            .get("https://api.hetzner.cloud/v1/zones")
            .header("Authorization", Self::auth_header(apitoken))
            .send()
            .await?;

        let zones = response.json::<Zones>().await?.zones;

        info!("Received {} zones", zones.len());

        Ok(zones)
    }

    async fn get_rrsets(&self, apitoken: &str, zone: &Zone) -> Result<Vec<RRset>, Box<dyn Error>> {
        let response = self
            .client
            .get(format!(
                "https://api.hetzner.cloud/v1/zones/{}/rrsets",
                zone.id
            ))
            .header("Authorization", Self::auth_header(apitoken))
            .send()
            .await?;

        let rrsets = response.json::<RRsets>().await?.rrsets;

        info!("Received {} rrsets", rrsets.len());

        Ok(rrsets)
    }

    async fn update_rrset(
        &self,
        apitoken: &str,
        zone_id: &str,
        rr_name: &str,
        rr_type: &RecordType,
        body: &SetRecords,
    ) -> Result<(), Box<dyn Error>> {
        let response = self
            .client
            .post(format!(
                "https://api.hetzner.cloud/v1/zones/{zone_id}/rrsets/{rr_name}/{rr_type}/actions/set_records"
            ))
            .header("Authorization", Self::auth_header(apitoken))
            .json(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "set_records failed for rrset {rr_name}/{rr_type}: {status} — {body}"
            )
            .into());
        }

        info!("Successfully submitted set_records action for rrset {rr_name}/{rr_type}");

        Ok(())
    }
}

impl super::Provider for HetznerCloudProvider {
    fn update_ip(
        &self,
        domain_config: &DomainConfig,
        new_ip: std::net::IpAddr,
    ) -> Result<bool, Box<dyn Error>> {
        // Split domain into subdomain and zone (if applicable)
        let update_record_name = if let Some(subdomain) = domain_config
            .host
            .strip_suffix(domain_config.zone.name.as_str())
        {
            // Strip last remaining dot from subdomain
            subdomain.strip_suffix('.').unwrap_or(subdomain)
        } else {
            // Use the whole domain, which is denoted by @ in DNS
            "@"
        };

        // Determine type of record to update (A for IPv4 or AAAA for IPv6)
        let update_record_type = if new_ip.is_ipv4() {
            RecordType::A
        } else {
            RecordType::AAAA
        };

        info!(
            "Updating \"{}\" record of type {} in zone {} (ID: {})",
            domain_config.host, update_record_type, domain_config.zone.name, domain_config.zone.id
        );

        tokio::task::block_in_place(|| {
            block_on(async move {
                // Get all rrsets of specified zone
                let rrsets = self
                    .get_rrsets(&domain_config.apitoken, &domain_config.zone)
                    .await?;

                // Find the rrset with matching type and name
                let rrset = rrsets
                    .into_iter()
                    .find(|r| r.name == update_record_name && r.record_type == update_record_type)
                    .ok_or_else(|| {
                        format!("No matching rrset (name: {update_record_name}, type: {update_record_type})")
                    })?;

                let new_ip_str = new_ip.to_string();

                // If the value is already correct, skip the update
                if rrset.records.iter().any(|r| r.value == new_ip_str) {
                    info!(
                        "RRset \"{update_record_name}\" of type {update_record_type} in zone {} (ID: {}) does not need to be updated",
                        domain_config.zone.name,
                        domain_config.zone.id
                    );
                    return Ok(false);
                }

                let update_body = SetRecords {
                    records: vec![RecordValue { value: new_ip_str }],
                };

                self.update_rrset(
                    &domain_config.apitoken,
                    &domain_config.zone.id,
                    &rrset.name,
                    &update_record_type,
                    &update_body,
                )
                .await?;

                Ok(true)
            })
        })
    }
}
