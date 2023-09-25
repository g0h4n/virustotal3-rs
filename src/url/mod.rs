use reqwest::Client;
use serde_json::{from_str,Value};
use super::{VtClient,UrlScanResponse};

impl <'a>VtClient<'a> {
    /// Scan an URL
    /// <https://developers.virustotal.com/reference/scan-url>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// let url = "https://example.com";
    /// vt.scan_url(url).await;
    /// ```
    pub async fn scan_url(self, target_url: &str) -> UrlScanResponse {
        let url = [self.endpoint, "/urls"].join("");
        let resp = Client::new()
            .post(&url)
            .header("x-apikey", self.api_key)
            .form(&[("url", target_url)])
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        //println!("{:?}",&resp);
        let text: &str = &resp.text().await.unwrap();
        from_str(text).unwrap()
    }

    //Object {"data": Object {"id": String("u-cff883d03914297b9800ec6beef5f41ecdd1666432104a35357af9d3b55720e3-1678882783"), "links": Object {"self": String("https://www.virustotal.com/api/v3/analyses/u-cff883d03914297b9800ec6beef5f41ecdd1666432104a35357af9d3b55720e3-1678882783")}, "type": String("analysis")}}

    /// Retrieve URL scan reports
    /// <https://developers.virustotal.com/reference/url-info>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "Resource ID";
    /// vt.report_url(resource).await;
    /// ```
    pub async fn report_url(self, resource: &str) -> Value {
        let url = [self.endpoint, "/urls/", resource].join("");
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }
}
