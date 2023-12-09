use super::{FileRescanResponse, FileScanResponse, VtClient};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{from_str, Value};

impl<'a> VtClient<'a> {
    /// Upload and scan a file
    /// <https://developers.virustotal.com/reference/files-scan>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// // Not async function to send file
    /// let vt = VtClient::new("Your API Key");
    /// vt.scan_file("eicar.txt")?;
    /// ```
    pub fn scan_file(self, filename: &str) -> Result<FileScanResponse> {
        let form = reqwest::blocking::multipart::Form::new()
            .file("file", filename)
            .context("File not found")?;

        let url = format!("{}/files", self.endpoint);
        let resp = reqwest::blocking::Client::new()
            .post(url)
            .header("x-apikey", self.api_key)
            .header("accept", "application/json")
            .header("content-type", "multipart/form-data")
            .multipart(form)
            .send()
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text()?;
        Ok(from_str(text)?)
    }

    /// Retrieve file scan reports
    /// <https://developers.virustotal.com/reference/file-info>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.get_report_file("SHA-256, SHA-1 or MD5 identifying the file").await?;
    /// ```
    pub async fn get_report_file(self, resource: &str) -> Result<Value> {
        let url = &[self.endpoint, "/files/", resource].join("");
        let resp = Client::new()
            .get(url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        Ok(from_str(text)?)
    }

    /// Rescanning already submitted files
    /// <https://developers.virustotal.com/reference/files-analyse>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// vt.rescan_file("SHA-256, SHA-1 or MD5 identifying the file").await?;
    /// ```
    pub async fn rescan_file(self, resource: &str) -> Result<FileRescanResponse> {
        let url = format!("{}/files/{resource}/analyse", self.endpoint);
        let resp = Client::new()
            .post(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        Ok(from_str(text)?)
    }
}
