use super::{DomainReportResponse, VtClient};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::from_str;

impl<'a> VtClient<'a> {
    /// Retrieves a domain report
    /// <https://developers.virustotal.com/reference/domain-info>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.report_domain("example.com").await?;
    /// ```
    pub async fn report_domain(self, domain: &'a str) -> Result<DomainReportResponse> {
        let url = format!("{}/domains/{domain}", self.endpoint);
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text = resp.text().await?;
        Ok(from_str(&text)?)
    }
}
