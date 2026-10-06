//! `onv-lease-expire`, the host timer (omnuv's modular design, A3): one run,
//! from onv-lease-expire.timer every minute. The library beside it is the
//! whole of it.

#[tokio::main(flavor = "current_thread")]
async fn main() {
    std::process::exit(onv_lease_expire::cli().await);
}
