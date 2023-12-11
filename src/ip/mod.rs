use super::{IpReportResponse, VtClient};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::from_str;

impl<'a> VtClient<'a> {
    /// Retrieve an IP address report
    /// <https://developers.virustotal.com/reference/ip-info>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.report_ip_address("192.168.2.1").await?;
    /// ```
    pub async fn report_ip_address(self, ip_address: &str) -> Result<IpReportResponse> {
        let url = format!("{}/ip_addresses/{ip_address}", self.endpoint);
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        Ok(from_str(text)?)
    }
}
