//! Genesis Mesh Connect's network computer on a headless Linux server.
//!
//! `init` creates a network here, or `restore` brings one back from a recovery
//! file; `run` then keeps it available under systemd. `pair`, `status`,
//! `connection` and `recovery` talk to the running service through a control
//! socket in its state directory that only the service's own user can open.
//! The web UI, phone and network never reach these operations.
#[cfg(unix)]
mod node;

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(error) = node::main(std::env::args().skip(1).collect()).await {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("The Connect node runs on Linux servers.");
    std::process::exit(1);
}
