//! <p align="center">
//! <img width="60%" src="https://raw.githubusercontent.com/g0h4n/virustotal3-rs/main/img/logo_virustotal3-rs.png">
//! </p>
//!
//! VirusTotal API `version 3` written in Rust inspired by the `version 2`: <https://github.com/owlinux1000/virustotal.rs>.
//!
//! Official API documentation: <https://developers.virustotal.com/reference/scan-url>
//!
//! Use "**VtClient**" struct.
//!
//! # Example
//!
//! ```
//! use virustotal3::*;
//!
//! let vt = VtClient::new("Your API Key");
//! let url = "https://example.com";
//! vt.scan_url(&url).await?;
//! ```
//!

use serde::Deserialize;
use serde_json::Value;

/// A set of scanning an URL
///
/// # Example how to scan an URL
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let url = "https://example.com/";
/// vt.scan_url(&url).await?;
/// ```
///
/// # Example how to retrieve URL scan reports
///
/// ```
/// use virustotal3::VtClient;///
///
/// let vt = VtClient::new("Your API Key");
/// let resource = "Resource ID";
/// vt.report_url(&resource).await?;
/// ```
///
/// More information here: [`vtClient::url`](../struct.VtClient.html)
pub mod url;

/// A set of reporting domain
///
/// # Example how to retrieves a domain report
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let domain = "example.com";
/// vt.report_domain(&domain).await?;
/// ```
///
/// More informations here: [`vtClient::domain`](../struct.VtClient.html)
pub mod domain;

/// A set of repoting ip
///
/// # Example how to retrieve an IP address report
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let ip = "192.168.2.1";
/// vt.report_ip_address(&ip).await?;
/// ```
///
/// More information here: [`vtClient::ip`](../struct.VtClient.html)
pub mod ip;

/// A set of scanning a file
///
/// # Example how to post and scan file
/// **WARNING**: This function isn't async function
///
/// **scan_file()** use [`reqwest::blocking`](https://docs.rs/reqwest/latest/reqwest/blocking/)
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let filename = "eicar.txt";
/// vt.scan_file(&filename)?;
/// ```
///
/// # Example how to retrieve file scan reports
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let hash = "SHA-256, SHA-1 or MD5 identifying the file";
/// vt.get_report_file(&hash).await?;
/// ```
///
/// # Example how to rescanning already submitted files
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let resource = "Resource file ID";
/// vt.rescan_file(resource).await?;
/// ```
///
/// More information here: [`vtClient::file`](../struct.VtClient.html)
pub mod file;

/// A set of putting a comment
///
/// # Example how to post new comment
///  
/// ```
/// use virustotal3::{VtClient, VtType};
///
/// let vt = VtClient::new("Your API Key");
/// let resource = "The resource ID where you want to put comments";
/// let vt_type = VtType::File; // Type of the resource
/// let comment = "This is a test";
/// vt.put_comment(resource, &comment, &vt_type).await?;
/// ```
///
/// # Example how to get comments
///
/// ```
/// use virustotal3::{VtClient, VtType};
///
/// let vt = VtClient::new("Your API Key");
/// let resource = "The resource ID where to get all comments";
/// let vt_type = VtType::File; // Type of the resource
/// vt.get_comment(&resource, &vt_type).await?;
/// ```
///
/// # Example how to delete comment
///
/// ```
/// use virustotal3::VtClient;
///
/// let vt = VtClient::new("Your API Key");
/// let resource = "The resource ID of the comment to delete";
/// vt.delete_comment(&resource).await?;
/// ```
///
/// More information here: [`vtClient::comment`](../struct.VtClient.html)
pub mod comment;

/// Comments structs
/// Example: <https://github.com/seanmonstar/reqwest/blob/master/examples/json_typed.rs>
#[derive(Debug, Deserialize)]
pub struct CommentGetResponse {
    pub meta: Meta,
    pub data: Vec<Comment>,
    pub links: ScanLink,
}

#[derive(Debug, Deserialize)]
pub struct CommentPutResponse {
    pub data: Comment,
}

#[derive(Debug, Deserialize)]
pub struct Meta {
    pub count: u32,
}

#[derive(Debug, Deserialize)]
pub struct Comment {
    pub attributes: CommentAttributes,
    #[serde(rename = "type")]
    pub vtype: String,
    pub id: String,
    pub links: ScanLink,
}

#[derive(Debug, Deserialize)]
pub struct CommentAttributes {
    pub date: u32,
    pub text: String,
    pub votes: CommentVote,
    pub html: String,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CommentVote {
    pub positive: u32,
    pub abuse: u32,
    pub negative: u32,
}

/// Domains structs
#[derive(Debug, Deserialize)]
pub struct DomainReportResponse {
    pub data: DomainReportData,
}

#[derive(Debug, Deserialize)]
pub struct DomainReportData {
    pub attributes: DomainAttributes,
    #[serde(rename = "type")]
    pub vtype: String,
    pub id: String,
    pub links: ScanLink,
}

#[derive(Debug, Deserialize)]
pub struct DomainAttributes {
    pub last_dns_records: Option<Value>,
    pub jarm: Option<String>,
    pub whois: Option<String>,
    pub last_https_certificate_date: Option<Value>,
    pub tags: Option<Vec<Value>>,
    pub popularity_ranks: Option<Value>,
    pub last_analysis_date: Option<u32>,
    pub last_dns_records_date: Option<u32>,
    pub last_analysis_stats: Option<LastAnalysisStats>,
    pub whois_date: Option<u32>,
    pub reputation: Option<Value>,
    pub registrar: Option<String>,
    pub last_analysis_results: Option<Value>,
    pub tld: Option<String>,
    pub last_modification_date: Option<u32>,
    pub last_https_certificate: Option<Value>,
    pub categories: Option<Value>,
    pub total_votes: Option<TotalVotes>,
}

#[derive(Debug, Deserialize)]
pub struct PopularityRanks {
    pub majestic: Option<Rank>,
    pub statvoo: Option<Rank>,
    pub alexa: Option<Rank>,
    pub cisco_umbrella: Option<Rank>,
    pub quantcast: Option<Rank>,
}

#[derive(Debug, Deserialize)]
pub struct Rank {
    pub timestamp: u32,
    pub rank: u32,
}

#[derive(Debug, Deserialize)]
pub struct LastAnalysisStats {
    pub harmless: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub timeout: u32,
}

#[derive(Debug, Deserialize)]
pub struct TotalVotes {
    pub harmless: u32,
    pub malicious: u32,
}

/// IP structs
#[derive(Debug, Deserialize)]
pub struct IpReportResponse {
    pub data: IpReportData,
}

#[derive(Debug, Deserialize)]
pub struct IpReportData {
    pub attributes: IpAttributes,
    #[serde(rename = "type")]
    pub vtype: String,
    pub id: String,
    pub links: ScanLink,
}

#[derive(Debug, Deserialize)]
pub struct IpAttributes {
    pub whois: Option<Value>,
    pub tags: Option<Vec<Value>>,
    pub last_analysis_date: Option<u32>,
    pub last_analysis_stats: Option<LastAnalysisStats>,
    pub whois_date: Option<u32>,
    pub last_analysis_results: Option<Value>,
    pub reputation: Option<u32>,
    pub last_modification_date: Option<u32>,
    pub total_votes: Option<TotalVotes>,
}

/// URLs structs
#[derive(Debug, Deserialize)]
pub struct UrlScanResponse {
    pub data: UrlScanData,
}

#[derive(Debug, Deserialize)]
pub struct UrlScanData {
    #[serde(rename = "type")]
    pub vtype: String,
    pub id: String,
    pub links: ScanLink,
}

#[derive(Debug, Deserialize)]
pub struct ScanLink {
    #[serde(rename = "self")]
    pub vself: String,
}

/// Files structs
#[derive(Debug, Deserialize)]
pub struct FileScanResponse {
    pub data: FileScanResponseData,
}

#[derive(Debug, Deserialize)]
pub struct FileRescanResponse {
    pub data: FileScanResponseData,
}

#[derive(Debug, Deserialize)]
pub struct FileScanResponseData {
    #[serde(rename = "type")]
    pub vtype: String,
    pub id: String,
    pub links: ScanLink,
}

/// VirusTotal resource type
#[derive(Copy, Debug, Clone)]
pub enum VtType {
    File,
    Url,
    Domain,
    Ip,
}

/// Virus Total web client
/// <https://www.virustotal.com/api/v3>
#[derive(Copy, Clone)]
pub struct VtClient<'a> {
    /// Your API key for access to VirusTotal
    api_key: &'a str,

    /// The versioned API endpoint to query
    endpoint: &'a str,
}
impl<'a> VtClient<'a> {
    pub fn new(api_key: &'a str) -> Self {
        VtClient {
            api_key,
            endpoint: "https://www.virustotal.com/api/v3",
        }
    }
}
