//! **The timer's own Proxmox client** (omnuv's modular design, A3): the
//! three calls a leased machine's stop makes (`onv_driver_proxmox::leased::
//! Api`), over the pinned TLS every connection to the hypervisor uses, with
//! the timer's token and nothing else. The agent's client is the agent's;
//! this one holds no image store, no opening book and no Core.

use onv_driver_proxmox::leased::{refusal_text, Api};

#[derive(serde::Deserialize)]
struct Envelope<T> {
    data: T,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    auth: omnuv_protocol::Redacted,
    /// `<user>@<realm>!<name>`: not a secret, and what a refusal names.
    token_id: String,
}

impl Client {
    /// A client for `api_url`, its certificate pinned to `fingerprint`, that
    /// asks as `token_id`.
    pub fn new(api_url: &str, fingerprint: Option<&str>, token_id: &str, token_secret: &str) -> anyhow::Result<Self> {
        let tls = onv_core_link::tls::config(fingerprint)?;
        Ok(Self {
            http: onv_core_link::tls::client(tls)?,
            base: api_url.trim_end_matches('/').to_string(),
            auth: format!("PVEAPIToken={token_id}={token_secret}").into(),
            token_id: token_id.to_string(),
        })
    }

    /// The token this client asks as, without its secret.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// One request's `data`, or what Proxmox said, the token scrubbed.
    async fn send<T: serde::de::DeserializeOwned>(&self, method: reqwest::Method, path: &str) -> anyhow::Result<T> {
        let mut req = self
            .http
            .request(method.clone(), format!("{}/api2/json{path}", self.base))
            .header("Authorization", self.auth.expose());
        if method == reqwest::Method::POST {
            req = req.form(&[] as &[(&str, &str)]);
        }
        let res = req.send().await.map_err(|e| anyhow::anyhow!("{method} {path}: {}", transport(&e)))?;
        let status = res.status();
        if !status.is_success() {
            let reason = res
                .extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
            let body = res.text().await.unwrap_or_default();
            let said = refusal_text(status.as_u16(), status.canonical_reason(), reason.as_deref(), &body, &self.auth);
            anyhow::bail!("{method} {path}: {said}");
        }
        Ok(res.json::<Envelope<T>>().await?.data)
    }
}

/// A request that never got an answer, with every cause reqwest knows. The
/// URL carries no credential (the token is a header).
fn transport(e: &reqwest::Error) -> String {
    let mut said = e.to_string();
    let mut cause = std::error::Error::source(e);
    while let Some(c) = cause {
        said.push_str(": ");
        said.push_str(&c.to_string());
        cause = c.source();
    }
    said
}

impl Api for Client {
    async fn get_json<T: serde::de::DeserializeOwned + Send>(&self, path: &str) -> anyhow::Result<T> {
        self.send(reqwest::Method::GET, path).await
    }

    async fn post_empty(&self, path: &str) -> anyhow::Result<String> {
        self.send(reqwest::Method::POST, path).await
    }

    /// Up to 600 looks about a second apart, as the agent waits for a stop:
    /// the unit's TimeoutStartSec (15 min) is set above it.
    async fn wait_task(&self, node: &str, upid: &str) -> anyhow::Result<()> {
        let encoded: String = upid
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect();
        for _ in 0..600 {
            let v: serde_json::Value = self.get_json(&format!("/nodes/{node}/tasks/{encoded}/status")).await?;
            if v.get("status").and_then(|s| s.as_str()) == Some("stopped") {
                let exit = v.get("exitstatus").and_then(|s| s.as_str()).unwrap_or("unknown");
                if exit == "OK" {
                    return Ok(());
                }
                anyhow::bail!("proxmox task failed: {exit}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await; // wait: a task's status, polled
        }
        anyhow::bail!("proxmox task {upid} did not finish in 600 looks (about 10 minutes)")
    }
}
