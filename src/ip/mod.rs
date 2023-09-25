use reqwest::Client;
use serde_json::from_str;
use super::{VtClient,IpReportResponse};

impl <'a>VtClient<'a> {
    /// Retrieve an IP address report
    /// <https://developers.virustotal.com/reference/ip-info>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// vt.report_ip_address("192.168.2.1").await;
    /// ```
    pub async fn report_ip_address(self, ip_address: &str) -> IpReportResponse {
        let url = [self.endpoint, "/ip_addresses/", ip_address].join("");
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }            
}
