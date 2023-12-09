use super::{CommentGetResponse, CommentPutResponse, VtClient, VtType};
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{from_str, json};

impl<'a> VtClient<'a> {
    /// POST comment on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/files-comments-post>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::{VtClient, VtType};
    ///
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID where you want to put comments";
    /// let vt_type = VtType::File;
    /// let comment = "This is a test";
    /// vt.put_comment(&resource, &comment, &vt_type).await?;
    /// ```
    pub async fn put_comment(
        self,
        resource: &str,
        comment: &str,
        vt_type: &VtType,
    ) -> Result<CommentPutResponse> {
        let url = match vt_type {
            VtType::File => {
                format!("{}/files/{resource}/comments", self.endpoint)
            }
            VtType::Url => {
                format!("{}/urls/{resource}/comments", self.endpoint)
            }
            VtType::Domain => {
                format!("{}/domains/{resource}/comments", self.endpoint)
            }
            VtType::Ip => {
                format!("{}/ip-address/{resource}/comments", self.endpoint)
            }
        };
        let datas = json!({
            "data": {
              "type": "comment",
              "attributes": {
                  "text": comment
              }
            }
        });
        let resp = Client::new()
            .post(&url)
            .header("x-apikey", self.api_key)
            .json(&datas)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        Ok(from_str(text)?)
    }

    /// GET comments on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/files-comments-get>
    /// <https://developers.virustotal.com/reference/urls-comments-get>
    /// <https://developers.virustotal.com/reference/domains-comments-get>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::{VtClient, VtType};
    ///
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID where to get all comments";
    /// let vt_type = VtType::File;
    /// vt.get_comment(&resource, &vt_type).await?;
    /// ```
    pub async fn get_comment(self, resource: &str, vt_type: &VtType) -> Result<CommentGetResponse> {
        let url = match vt_type {
            VtType::File => {
                format!("{}/files/{resource}/comments", self.endpoint)
            }
            VtType::Url => {
                format!("{}/urls/{resource}/comments", self.endpoint)
            }
            VtType::Domain => {
                format!("{}/domains/{resource}/comments", self.endpoint)
            }
            VtType::Ip => {
                format!("{}/ip-address/{resource}/comments", self.endpoint)
            }
        };
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        Ok(from_str(text)?)
    }

    /// DELETE comment on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/comment-id-delete>
    ///
    /// # Example
    ///
    /// ```
    /// use virustotal3::VtClient;
    ///
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID of the comment to delete";
    /// vt.delete_comment(&resource).await;
    /// ```
    pub async fn delete_comment(self, resource: &str) -> Result<bool> {
        let url = format!("{}/comments/{resource}", self.endpoint);
        let resp = Client::new()
            .delete(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await
            .context("Error! Probably maximum request limit achieved!")?;
        let text: &str = &resp.text().await?;
        //println!("[-] Comment '{resource}' found: {}", text.contains("NotFoundError"));
        Ok(!text.contains("NotFoundError"))
    }
}
