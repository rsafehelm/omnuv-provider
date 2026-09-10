//! # Omnuv Workload Agent
//!
//! The third tier. Runs *inside* a machine the marketplace owns — an inference
//! worker first, gateways and recipe deployments later — and reports what only
//! the inside can see, upward to its Provider Agent.
//!
//! **Never inside a buyer's machine.** The buyer owns that machine, could stop
//! or forge anything running in it, and its silence would be indistinguishable
//! from a dead machine. Billing takes allocation time from the ledger and
//! tokens from the gateway; neither needs a guest to be honest.
//!
//! ## Why it has to exist
//!
//! A passed-through GPU is bound to `vfio-pci` on the host. The host has no
//! NVIDIA driver for it, so `nvidia-smi` there cannot see the card at all.
//! Utilisation, real VRAM, temperature and power exist *only* in the guest.
//! Until now the host guessed VRAM from a static table of seven device names.
//!
//! ## Direction
//!
//! It writes a file. That is the whole transport.
//!
//! The Provider Agent reads it through the hypervisor's guest agent, on the
//! reconcile tick it already runs — the same mechanism the recipe install
//! report uses, needing only `VM.GuestAgent.FileRead`. So this process opens no
//! socket, listens on nothing, holds no credential, and needs no route to
//! anywhere. There is nothing here to authenticate because there is nothing
//! here to reach.
//!
//! It also keeps working when the machine's own networking does not, which is
//! exactly when someone wants to know what a machine is doing.
//!
//! Reports still aggregate on the way up: the Provider Agent folds this into
//! the one status report it already sends, so Core scales with the number of
//! providers rather than the number of machines.

use omnuv_protocol::{
    GpuTelemetry, ModelProgress, ModelStage, ServingStats, WorkloadHealth, WorkloadReport,
};
use std::io::Write as _;
use std::time::{Duration, Instant};

/// Faster than the Provider Agent reads, so a read never finds nothing new.
const INTERVAL: Duration = Duration::from_secs(15);

/// On `tmpfs`, deliberately: a reboot must not leave yesterday's report behind
/// looking current, and this is state about *now* that should not survive the
/// process that produced it.
const STATUS_PATH: &str = "/run/omnuv/workload.json";

/// Beyond this, a worker that answers is still not somewhere to send traffic.
/// The number is deliberately generous — `/v1/models` is a trivial handler, so
/// two seconds means the event loop is starved, not that the model is large.
const DEGRADED_ABOVE: Duration = Duration::from_millis(2000);

struct Config {
    workload_id: String,
    vllm_url: String,
    cache_dir: String,
}

impl Config {
    /// From the environment, which cloud-init writes. The id is required: a
    /// workload agent that invented its own would report telemetry against a
    /// machine that does not exist.
    fn from_env() -> anyhow::Result<Self> {
        let need = |k: &str| {
            std::env::var(k).map_err(|_| anyhow::anyhow!("{k} is not set; cloud-init writes it"))
        };
        Ok(Self {
            workload_id: need("OMNUV_WORKLOAD_ID")?,
            vllm_url: std::env::var("OMNUV_VLLM_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000".into()),
            cache_dir: std::env::var("OMNUV_CACHE_DIR")
                .unwrap_or_else(|_| "/opt/omnuv/hf".into()),
        })
    }
}

// ---------------------------------------------------------------------------
// Parsing. Kept pure and separate from the I/O so it can be tested against the
// exact text these tools emit, which is the part that silently changes.
// ---------------------------------------------------------------------------

/// Parses `nvidia-smi --query-gpu=... --format=csv,noheader,nounits`.
///
/// `[N/A]` is a real value from this tool — an unsupported sensor, common for
/// power on consumer cards — and must become `None` rather than zero. A zero
/// would read as "idle at 0 W", which is a claim about the card instead of an
/// admission about the sensor.
fn parse_nvidia_smi(out: &str) -> Vec<GpuTelemetry> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let f: Vec<&str> = line.split(',').map(str::trim).collect();
            if f.len() < 7 {
                return None;
            }
            let num = |s: &str| s.parse::<f64>().ok();
            Some(GpuTelemetry {
                index: f[0].parse().ok()?,
                name: f[1].to_string(),
                vram_total_mib: num(f[2])? as u64,
                vram_used_mib: num(f[3]).unwrap_or(0.0) as u64,
                utilization_pct: num(f[4]).unwrap_or(0.0) as u32,
                temperature_c: num(f[5]).map(|v| v as u32),
                power_mw: num(f[6]).map(|w| (w * 1000.0) as u32),
            })
        })
        .collect()
}

/// Pulls the four counters worth having out of vLLM's Prometheus text.
///
/// Deliberately tolerant: it matches on the metric name before `{` and ignores
/// everything else in the exposition, so a vLLM release that adds, renames or
/// relabels other metrics does not blind us to these.
fn parse_vllm_metrics(body: &str) -> Option<ServingStats> {
    let mut running = None;
    let mut waiting = None;
    let mut prompt = 0u64;
    let mut generation = 0u64;

    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (key, value) = match line.rsplit_once(' ') {
            Some(kv) => kv,
            None => continue,
        };
        let name = key.split('{').next().unwrap_or(key).trim();
        let v: f64 = match value.trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        match name {
            "vllm:num_requests_running" => running = Some(v as u32),
            "vllm:num_requests_waiting" => waiting = Some(v as u32),
            "vllm:prompt_tokens_total" => prompt += v as u64,
            "vllm:generation_tokens_total" => generation += v as u64,
            _ => {}
        }
    }

    // Both gauges absent means this is not a vLLM exposition at all. Reporting
    // zeros then would say "idle", and idle is a placement signal.
    if running.is_none() && waiting.is_none() {
        return None;
    }
    Some(ServingStats {
        requests_running: running.unwrap_or(0),
        requests_waiting: waiting.unwrap_or(0),
        prompt_tokens_total: prompt,
        generation_tokens_total: generation,
    })
}

/// What the probe means.
///
/// The distinction an HTTP 200 cannot make is the point of this whole type: a
/// worker answering slowly is worse than one that is honestly still loading,
/// because the loading one is not in the routing table.
fn classify_health(reachable: bool, ok: bool, elapsed: Duration) -> WorkloadHealth {
    match (reachable, ok) {
        (false, _) => WorkloadHealth::Down,
        (true, false) => WorkloadHealth::Starting,
        (true, true) if elapsed > DEGRADED_ABOVE => WorkloadHealth::Degraded,
        (true, true) => WorkloadHealth::Serving,
    }
}

/// Where the model is, inferred from what is observable.
///
/// The weights are fetched inside a container we do not run, so there is no
/// progress bar to read. What is observable is the cache growing on disk and
/// the server starting to answer, and those two facts separate the three
/// stages well enough to stop `LOADING_MODEL` being opaque.
fn model_stage(serving: bool, delta_bytes: u64) -> ModelStage {
    if serving {
        ModelStage::Loaded
    } else if delta_bytes > 0 {
        ModelStage::Downloading
    } else {
        ModelStage::Loading
    }
}

/// Bytes under a directory. Walks rather than shelling out to `du`, so a
/// missing directory is 0 instead of an error on stderr, which is the normal
/// state for the first minute of a machine's life.
fn dir_bytes(path: &str) -> u64 {
    fn walk(p: &std::path::Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(p) else {
            return 0;
        };
        entries
            .flatten()
            .map(|e| match e.file_type() {
                Ok(t) if t.is_dir() => walk(&e.path()),
                Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => 0,
            })
            .sum()
    }
    walk(std::path::Path::new(path))
}

// ---------------------------------------------------------------------------
// Collection and the loop.
// ---------------------------------------------------------------------------

fn read_gpus() -> Vec<GpuTelemetry> {
    let out = std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => parse_nvidia_smi(&String::from_utf8_lossy(&o.stdout)),
        // No driver yet, or no card. An empty list, never a fabricated one.
        _ => Vec::new(),
    }
}

async fn probe(client: &reqwest::Client, vllm_url: &str) -> (WorkloadHealth, Option<ServingStats>) {
    let started = Instant::now();
    let health = match client.get(format!("{vllm_url}/v1/models")).send().await {
        Ok(r) => classify_health(true, r.status().is_success(), started.elapsed()),
        Err(_) => WorkloadHealth::Down,
    };
    let serving = match client.get(format!("{vllm_url}/metrics")).send().await {
        Ok(r) => match r.text().await {
            Ok(b) => parse_vllm_metrics(&b),
            Err(_) => None,
        },
        Err(_) => None,
    };
    (health, serving)
}

/// Write, then rename. The Provider Agent reads this file on its own schedule,
/// and a reader that catches a half-written file gets invalid JSON — which
/// parses to "not known" and is therefore harmless, but happens on every single
/// tick if the write is not atomic. Rename within one filesystem is.
fn write_atomically(path: &str, report: &WorkloadReport) -> std::io::Result<()> {
    let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("/run"));
    std::fs::create_dir_all(dir)?;
    let tmp = format!("{path}.new");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string(report)?.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::from_env()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let started = Instant::now();
    let mut last_bytes = dir_bytes(&cfg.cache_dir);
    let mut last_health: Option<WorkloadHealth> = None;

    eprintln!("omnuv-workloadd: {} reporting to {STATUS_PATH}", cfg.workload_id);

    loop {
        let (health, serving) = probe(&client, &cfg.vllm_url).await;
        let bytes = dir_bytes(&cfg.cache_dir);
        let delta = bytes.saturating_sub(last_bytes);
        last_bytes = bytes;

        let loaded = health == WorkloadHealth::Serving || health == WorkloadHealth::Degraded;
        let report = WorkloadReport {
            workload_id: cfg.workload_id.clone(),
            uptime_s: started.elapsed().as_secs(),
            health,
            // Once it serves, progress is not news any more.
            model: (!loaded).then(|| ModelProgress {
                stage: model_stage(loaded, delta),
                cached_bytes: bytes,
                delta_bytes: delta,
            }),
            gpus: read_gpus(),
            serving,
        };

        if let Err(e) = write_atomically(STATUS_PATH, &report) {
            // Never fatal. A full disk or a missing directory must not end the
            // process: the agent's own probe still decides the worker's state,
            // and a machine that stops reporting is a smaller problem than one
            // that stops running.
            eprintln!("omnuv-workloadd: writing {STATUS_PATH}: {e}");
        }

        if last_health != Some(health) {
            eprintln!("omnuv-workloadd: health {last_health:?} -> {health:?}");
            last_health = Some(health);
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real output from `nvidia-smi` on a 3090, including the `[N/A]` this tool
    /// emits for a sensor it cannot read.
    #[test]
    fn parses_what_nvidia_smi_actually_prints() {
        let out = "\
0, NVIDIA GeForce RTX 3090, 24576, 21000, 87, 71, 305.50
1, NVIDIA GeForce RTX 3090, 24576, 0, 0, 38, [N/A]
";
        let gpus = parse_nvidia_smi(out);
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].name, "NVIDIA GeForce RTX 3090");
        assert_eq!(gpus[0].vram_total_mib, 24576);
        assert_eq!(gpus[0].utilization_pct, 87);
        assert_eq!(gpus[0].power_mw, Some(305_500));
        // The unreadable sensor is absent, not zero: zero would be a claim
        // about the card rather than about the sensor.
        assert_eq!(gpus[1].power_mw, None);
        assert_eq!(gpus[1].temperature_c, Some(38));
    }

    #[test]
    fn a_card_with_no_driver_yields_no_gpus_rather_than_a_guess() {
        assert!(parse_nvidia_smi("").is_empty());
        assert!(parse_nvidia_smi("NVIDIA-SMI has failed because it couldn't communicate").is_empty());
    }

    #[test]
    fn parses_vllm_exposition_and_ignores_the_rest_of_it() {
        let body = "\
# HELP vllm:num_requests_running Number of requests in model execution batches.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name=\"Qwen/Qwen3-8B\"} 2.0
vllm:num_requests_waiting{model_name=\"Qwen/Qwen3-8B\"} 5.0
vllm:prompt_tokens_total{model_name=\"Qwen/Qwen3-8B\"} 12345.0
vllm:generation_tokens_total{model_name=\"Qwen/Qwen3-8B\"} 6789.0
python_gc_objects_collected_total{generation=\"0\"} 9999.0
";
        let s = parse_vllm_metrics(body).expect("vLLM metrics");
        assert_eq!(s.requests_running, 2);
        assert_eq!(s.requests_waiting, 5);
        assert_eq!(s.prompt_tokens_total, 12345);
        assert_eq!(s.generation_tokens_total, 6789);
    }

    /// Anything else answering on that port is not vLLM. Reporting zeros would
    /// say "idle", and idle is a signal placement acts on.
    #[test]
    fn something_that_is_not_vllm_reports_nothing_rather_than_idle() {
        assert!(parse_vllm_metrics("").is_none());
        assert!(parse_vllm_metrics("# HELP go_gc_duration_seconds\ngo_goroutines 12").is_none());
    }

    #[test]
    fn health_separates_slow_from_healthy_and_from_still_loading() {
        let quick = Duration::from_millis(20);
        let slow = Duration::from_secs(9);
        assert_eq!(classify_health(true, true, quick), WorkloadHealth::Serving);
        assert_eq!(classify_health(true, true, slow), WorkloadHealth::Degraded);
        // Connected but not serving: vLLM is up and still loading weights.
        assert_eq!(classify_health(true, false, quick), WorkloadHealth::Starting);
        assert_eq!(classify_health(false, false, quick), WorkloadHealth::Down);
    }

    #[test]
    fn stage_follows_what_is_observable() {
        assert_eq!(model_stage(true, 0), ModelStage::Loaded);
        assert_eq!(model_stage(false, 4096), ModelStage::Downloading);
        // Nothing arriving and not yet serving: the bytes are down, the weights
        // are going into VRAM. This is the window that used to be opaque.
        assert_eq!(model_stage(false, 0), ModelStage::Loading);
    }

    #[test]
    fn a_missing_cache_directory_is_zero_bytes_not_an_error() {
        assert_eq!(dir_bytes("/nonexistent/omnuv/cache"), 0);
    }
}

#[cfg(test)]
mod write_tests {
    use super::*;

    /// A reader on its own schedule must never see half a file. Without the
    /// rename this is not rare — it is every tick the two happen to overlap.
    #[test]
    fn the_report_is_written_whole_or_not_at_all() {
        let dir = std::env::temp_dir().join(format!("omnuv-wl-{}", std::process::id()));
        let path = dir.join("workload.json");
        let p = path.to_str().unwrap();

        let report = WorkloadReport {
            workload_id: "w1".into(),
            uptime_s: 42,
            health: WorkloadHealth::Serving,
            model: None,
            gpus: vec![],
            serving: None,
        };
        write_atomically(p, &report).expect("writes");

        let back: WorkloadReport =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).expect("whole JSON");
        assert_eq!(back.uptime_s, 42);

        // Overwriting leaves no temporary behind for the agent to trip over.
        write_atomically(p, &report).expect("overwrites");
        assert!(!std::path::Path::new(&format!("{p}.new")).exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The directory is on tmpfs and does not exist on a fresh boot.
    #[test]
    fn a_missing_directory_is_created_rather_than_fatal() {
        let dir = std::env::temp_dir().join(format!("omnuv-wl-new-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let path = dir.join("deeper").join("workload.json");
        let report = WorkloadReport {
            workload_id: "w1".into(),
            uptime_s: 1,
            health: WorkloadHealth::Starting,
            model: None,
            gpus: vec![],
            serving: None,
        };
        write_atomically(path.to_str().unwrap(), &report).expect("creates the directory");
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
