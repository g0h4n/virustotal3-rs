use reqwest::Client;
use serde_json::from_str;
use super::{VtClient,DomainReportResponse};

impl <'a>VtClient<'a> {
    /// Retrieves a domain report 
    /// <https://developers.virustotal.com/reference/domain-info>
    /// 
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// vt.report_domain("example.com").await;
    /// ```
    pub async fn report_domain(self, domain: &'a str) -> DomainReportResponse {
        let url = [self.endpoint, "/domains/", domain].join("");
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text = resp.text().await.unwrap();
        from_str(&text).unwrap()
    }
}