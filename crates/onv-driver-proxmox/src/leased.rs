//! **A leased machine stopped**, over any Proxmox client (omnuv's modular
//! design, A3). The agent's lease task and the host timer stop the same
//! machines by the same rule, and since A3 they are two binaries holding two
//! tokens: the agent's client (the agent's `proxmox::Client`) and the
//! timer's own, much smaller one (`onv-lease-expire`). So the rule is here,
//! once, written against the three calls it makes, and each client answers
//! them ([`Api`]).
//!
//! ```text
//! which guests   every guest carrying the claim tag and the id's key, in
//!                the cluster's listing; none there is confirmed on every
//!                online node's own listing (PROVIDER-5)
//! which of them  the one whose description's first line is the whole stamp;
//!                a guest with the tag and another stamp is left, and said
//! when           its node's live status is not `stopped`
//! what           status/stop, and the task waited for. Nothing destroys
//! ```
//!
//! Moved from the agent's `teardown.rs` (`claimed_guests`, `live_status`) and
//! `lease.rs` (`stop_leased`, `Stops`) with no change to what is asked or
//! decided: the agent's methods of those names call these.

use std::future::Future;

/// **What Proxmox said when it refused a call** (the lifecycle phase 7
/// regression, nuc0, 26 September: the journal said "500 Internal Server
/// Error" and nothing else). `pve-http-server` answers a handler's `die` with
/// the message as the HTTP reason phrase, which reqwest keeps only as hyper's
/// extension, and some answers carry it in the body as well. Both are said:
/// the reason, then the body's `message`, or the body itself when it has none
/// (cut to 300 characters). **Never the token**: its id and secret are
/// replaced wherever Proxmox might have echoed them.
///
/// Moved from the agent's `proxmox.rs` (A3), taking the status as its number
/// and its canonical phrase so this crate needs no HTTP client.
pub fn refusal_text(
    status: u16,
    canonical: Option<&str>,
    reason: Option<&str>,
    body: &str,
    auth: &omnuv_protocol::Redacted,
) -> String {
    let mut said = status.to_string();
    let reason = reason.map(str::trim).filter(|r| !r.is_empty());
    let canonical = canonical.unwrap_or("");
    said.push(' ');
    said.push_str(reason.unwrap_or(canonical));
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(|m| m.trim().to_string()));
    let detail = match message {
        Some(m) => m,
        None => {
            let b = body.trim();
            if b == r#"{"data":null}"# { String::new() } else { b.to_string() }
        }
    };
    if !detail.is_empty() && Some(detail.as_str()) != reason {
        said.push_str(": ");
        said.push_str(&detail);
    }
    let mut said: String = said.chars().take(300).collect();
    // `PVEAPIToken=<id>=<secret>`: each part scrubbed on its own.
    let token = auth.expose().trim_start_matches("PVEAPIToken=");
    let (id, secret) = token.split_once('=').unwrap_or((token, ""));
    for part in [secret, id] {
        if part.len() >= 3 {
            said = said.replace(part, "<token>");
        }
    }
    said
}

/// The three things a stop asks of Proxmox: a read, a form post, and a wait
/// for the task a post started. Every error is the client's own words, with
/// the token scrubbed from them.
pub trait Api: Sync {
    /// `GET /api2/json{path}`, its `data`.
    fn get_json<T: serde::de::DeserializeOwned + Send>(&self, path: &str) -> impl Future<Output = anyhow::Result<T>> + Send;
    /// `POST /api2/json{path}` with no form, its `data` (a task id).
    fn post_empty(&self, path: &str) -> impl Future<Output = anyhow::Result<String>> + Send;
    /// The task `upid` on `node`, waited for until it ends; an error unless
    /// it ended OK.
    fn wait_task(&self, node: &str, upid: &str) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// A guest as a listing names it.
#[derive(Debug, Clone)]
pub struct Guest {
    pub node: String,
    pub vmid: u32,
    pub tags: Option<String>,
}

/// **Every guest carrying this claim**, across the cluster: the kind tag
/// and the id tag, both, as whole tokens. All of them, not the first —
/// "which one" is licence (a)'s question, and a listing that stopped at
/// the first could never ask it.
///
/// None in the cluster listing is confirmed against every online node's
/// live listing (PROVIDER-5): a miss is the dangerous answer, and a node that
/// cannot be read means absence cannot be concluded.
pub async fn claimed_guests<A: Api>(api: &A, kind: &str, id: &str) -> anyhow::Result<Vec<Guest>> {
    #[derive(serde::Deserialize)]
    struct ClusterVm {
        node: String,
        vmid: u32,
        #[serde(default)]
        tags: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct NodeVm {
        vmid: u32,
        #[serde(default)]
        tags: Option<String>,
    }
    // The key in either generation: a guest built before the whole key
    // carries the twelve-digit one alone (omnuv's 0235).
    let tagged = |tags: Option<&str>| {
        tags.is_some_and(|t| t.split(';').any(|x| x == kind) && onv_agent_lib::names::carries_key(t, id))
    };
    let vms: Vec<ClusterVm> = api.get_json("/cluster/resources?type=vm").await?;
    let found: Vec<Guest> = vms
        .into_iter()
        .filter(|v| tagged(v.tags.as_deref()))
        .map(|v| Guest { node: v.node, vmid: v.vmid, tags: v.tags })
        .collect();
    if !found.is_empty() {
        return Ok(found);
    }
    let nodes: Vec<serde_json::Value> = api.get_json("/nodes").await?;
    let mut live = Vec::new();
    for n in nodes.iter().filter(|n| n["status"].as_str() == Some("online")) {
        let Some(node) = n["node"].as_str() else { continue };
        let vms: Vec<NodeVm> = api.get_json(&format!("/nodes/{node}/qemu")).await.map_err(|e| {
            anyhow::anyhow!("{node} could not be listed, so this machine's absence cannot be concluded: {e}")
        })?;
        live.extend(
            vms.into_iter()
                .filter(|v| tagged(v.tags.as_deref()))
                .map(|v| Guest { node: node.to_string(), vmid: v.vmid, tags: v.tags }),
        );
    }
    Ok(live)
}

/// **A guest's power state as its node says it now**: `status/current`,
/// which asks qemu-server whether the process runs — the same check
/// Proxmox's own destroy makes before it refuses. Never the cluster
/// listing's `status`, which lags a start by up to pvestatd's interval.
/// A paused guest reads `running`, and is stopped like one.
pub async fn live_status<A: Api>(api: &A, node: &str, vmid: u32) -> anyhow::Result<String> {
    let now: serde_json::Value = api.get_json(&format!("/nodes/{node}/qemu/{vmid}/status/current")).await?;
    now.get("status")
        .and_then(|s| s.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("vm {vmid} on {node}: its node gave no power state, so it is not destroyed"))
}

/// What one stop of a leased machine did, guest by guest, for whoever logs it.
#[derive(Default)]
pub struct Stops<'a> {
    /// `vm <vmid> on <node>`, stopped by this call.
    pub stopped: Vec<String>,
    /// Guests carrying the claim that were left, and why: another stamp.
    pub refused: Vec<String>,
    /// How many guests carried the claim tag and its whole stamp, stopped
    /// by this call or already stopped. **Zero is not "nothing to do"**: a
    /// token that cannot see a guest (the host timer's, outside
    /// /pool/onv-buyers) lists the same as a guest that is gone, and the
    /// caller decides which answer it can give (R1 rule 9).
    pub claimed: usize,
    /// Told `vm <vmid> on <node>` just before its stop is sent, so a run
    /// that dies mid-stop has said what it was doing, and a machine already
    /// stopped says nothing at all.
    pub announce: Option<&'a (dyn Fn(&str) + Sync)>,
}

/// **A leased machine stopped**: every guest carrying its claim tag and
/// its whole stamp, stopped when its node says it is not. A guest with
/// the tag and another stamp is left alone and said. What was done is in
/// `out` even when a later guest fails; an error ends the call there, and
/// the caller tries the whole machine again on its next pass.
///
/// The power state is the node's live one (`status/current`), never the
/// cluster listing's, which lags. Stop only: nothing here destroys.
pub async fn stop_leased<A: Api>(api: &A, id: &str, out: &mut Stops<'_>) -> anyhow::Result<()> {
    let tag = onv_agent_lib::names::TAG_INSTANCE;
    for g in claimed_guests(api, tag, id).await? {
        let config: serde_json::Value = api.get_json(&format!("/nodes/{}/qemu/{}/config", g.node, g.vmid)).await?;
        let first = config.get("description").and_then(|d| d.as_str()).and_then(|d| d.lines().next());
        if first != Some(onv_agent_lib::names::stamped(tag, id).as_str()) {
            out.refused.push(format!(
                "vm {} on {} carries {id}'s tag but not its stamp (its first line reads {:?}); not stopped",
                g.vmid,
                g.node,
                first.unwrap_or("")
            ));
            continue;
        }
        out.claimed += 1;
        if live_status(api, &g.node, g.vmid).await? == "stopped" {
            continue;
        }
        if let Some(say) = out.announce {
            say(&format!("vm {} on {}", g.vmid, g.node));
        }
        let upid = api.post_empty(&format!("/nodes/{}/qemu/{}/status/stop", g.node, g.vmid)).await?;
        api.wait_task(&g.node, &upid).await?;
        out.stopped.push(format!("vm {} on {}", g.vmid, g.node));
    }
    Ok(())
}
