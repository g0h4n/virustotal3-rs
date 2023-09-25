use reqwest::Client;
use serde_json::{from_str,Value};
use super::{VtClient,FileScanResponse,FileRescanResponse};

impl <'a>VtClient<'a> {
    /// Upload and scan a file
    /// <https://developers.virustotal.com/reference/files-scan>
    /// 
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    ///
    /// // Not async function to send file
    /// let vt = VtClient::new("Your API Key");
    /// vt.scan_file("eicar.txt");
    /// ```
    pub fn scan_file(self, filename: &str) -> FileScanResponse {
        let form = reqwest::blocking::multipart::Form::new()
            .file("file", filename)
            .expect("File not found");

        let url = &[self.endpoint, "/files"].join("");
        let resp = reqwest::blocking::Client::new()
            .post(url)
            .header("x-apikey", self.api_key)
            .header("accept", "application/json")
            .header("content-type", "multipart/form-data")
            .multipart(form)
            .send()
            .expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().unwrap();
        from_str(&text).unwrap()
    }

    /// Retrieve file scan reports
    /// <https://developers.virustotal.com/reference/file-info>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.get_report_file("SHA-256, SHA-1 or MD5 identifying the file").await;
    /// ```
    pub async fn get_report_file(self, resource: &str) -> Value {
        let url = &[self.endpoint, "/files/", resource].join("");
        let resp = Client::new()
            .get(url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }
     
    /// Rescanning already submitted files
    /// <https://developers.virustotal.com/reference/files-analyse>
    /// 
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.rescan_file(resource).await;
    /// ```
    pub async fn rescan_file(self, resource: &str) -> FileRescanResponse {
        let url = [self.endpoint, "/files/", resource, "/analyse"].join("");
        let resp = Client::new()
            .post(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }
}
