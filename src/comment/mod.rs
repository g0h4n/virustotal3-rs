use reqwest::Client;
use serde_json::{json,from_str};
use super::{VtClient,VtType,CommentGetResponse,CommentPutResponse};

impl <'a>VtClient<'a> {
    /// POST comment on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/files-comments-post>
    /// 
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID where you want to put comments";
    /// let vt_type = VtType::File;
    /// let comment = "This is a test";
    /// vt.put_comment(&resource, &comment, &vt_type).await;
    /// ```
    pub async fn put_comment(self, resource: &str, comment: &str, vt_type: &VtType) -> CommentPutResponse {
        let url;
        match vt_type {
            VtType::File => {
                url = [self.endpoint, "/files/", resource, "/comments"].join("");
            },
            VtType::Url => {
                url = [self.endpoint, "/urls/", resource, "/comments"].join("");
            },
            VtType::Domain => {
                url = [self.endpoint, "/domains/", resource, "/comments"].join("");
            }
            VtType::Ip => {
                url = [self.endpoint, "/ip-address/", resource, "/comments"].join("");
            }
        }
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
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }
    
    /// GET comments on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/files-comments-get>
    /// <https://developers.virustotal.com/reference/urls-comments-get>
    /// <https://developers.virustotal.com/reference/domains-comments-get>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID where to get all comments";
    /// let vt_type = VtType::File;
    /// vt.get_comment(&resource, &vt_type).await;
    /// ```
    pub async fn get_comment(self, resource: &str, vt_type: &VtType) -> CommentGetResponse {
        let url;
        match vt_type {
            VtType::File => {
                url = [self.endpoint, "/files/", resource, "/comments"].join("");
            },
            VtType::Url => {
                url = [self.endpoint, "/urls/", resource, "/comments"].join("");
            },
            VtType::Domain => {
                url = [self.endpoint, "/domains/", resource, "/comments"].join("");
            }
            VtType::Ip => {
                url = [self.endpoint, "/ip-address/", resource, "/comments"].join("");
            }
        }
        let resp = Client::new()
            .get(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        from_str(&text).unwrap()
    }

    /// DELETE comment on Files or URLs or Domains
    /// <https://developers.virustotal.com/reference/comment-id-delete>
    ///
    /// # Example
    /// 
    /// ```
    /// use virustotal3::*;
    /// 
    /// let vt = VtClient::new("Your API Key");
    /// let resource = "The resource ID of the comment to delete";
    /// vt.delete_comment(&resource).await;
    /// ```
    pub async fn delete_comment(self, resource: &str) -> bool {
        let url = [self.endpoint, "/comments/", resource].join("");
        let resp = Client::new()
            .delete(&url)
            .header("x-apikey", self.api_key)
            .send()
            .await.expect("Error! Probably maximum request limit achieved!");
        let text: &str = &resp.text().await.unwrap();
        if text.contains("NotFoundError") {
            //println!("[-] Comment '{resource}' not found!");
            false
        }
        else {
            //println!("[+] Comment '{resource}' deleted!");
            true
        }
    }
}