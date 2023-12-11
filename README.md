# virustotal3-rs

<p align="center">
  <a href="https://crates.io/crates/virustotal3"><img alt="Crates.io" src="https://img.shields.io/crates/v/virustotal3?style=for-the-badge"></a>
  <img alt="GitHub" src="https://img.shields.io/github/license/g0h4n/virustotal3-rs?style=for-the-badge">
  <a href="https://twitter.com/intent/follow?screen_name=g0h4n_0" title="Follow" rel="nofollow"><img alt="Twitter Follow" src="https://img.shields.io/badge/TWITTER-g0h4n-white?style=for-the-badge"></a>
  <br>
</p>

<p align="center">
<img width="80%" src="img/logo_virustotal3-rs.png">
</p>

Library for virustotal API [version 3](https://developers.virustotal.com/reference/) written in Rust. :crab:

## Implemented Features

| Method | Resource                    | Description                        |
|:------:|:----------------------------|:-----------------------------------|
| GET    | /api/v3/files/{id}              | Retrieve file scan reports                   |
| POST   | /api/v3/files                   | Upload and scan a file                       |
| POST   | /api/v3/files/{id}/analyse      | Rescanning already submitted files           |
| GET    | /api/v3/urls/{id}               | Retrieve URL scan reports                    |
| POST   | /api/v3/urls                    | Scan an URL                                  |
| POST   | /api/v3/{type}/{id}/comments    | Make comments for a file or URL or Domain    |
| GET    | /api/v3/{type}/{id}/comments    | Get comments for a file or URL or Domain     |
| DELETE | /api/v3/comments/{id}           | Delete a comment for a file or URL or Domain |
| GET    | /api/v3/domains/{domain}        | Retrieves a domain report                    |
| GET    | /api/v3/ip_address/{ip-address} | Retrieve an IP address report                |

## Example

```rust
use virustotal3::VtClient;

#[tokio::main]
async fn main() {
    let api = "Your API KEY";
    let url = "The URL you want to check";
    let vt = VtClient::new(api);
    let res = vt.scan_url(&url).await;
    println!("{:?}", &res.data);
}
```

More examples in [doc.rs/virustotal3](https://docs.rs/virustotal3)

## Acknowledgements

* Thanks to [owlinux1000](https://github.com/owlinux1000) for inital work on virustotal API [version 2](https://github.com/owlinux1000/virustotal.rs).