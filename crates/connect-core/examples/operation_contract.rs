//! Explicit generation/check, never repairs a stale contract during checking.
#[cfg(feature = "operation-schemas")]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    let command = std::env::args().nth(1).unwrap_or_else(|| "check".into());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/connect-operations.json");
    let expected = connect_core::operations::schemas::document()?;
    match command.as_str() {
        "generate" => std::fs::write(path, expected)?,
        "check" => ensure!(
            std::fs::read_to_string(path)? == expected,
            "Stale operation schemas; review Rust changes and explicitly regenerate the contract"
        ),
        _ => anyhow::bail!("Use check or generate"),
    }
    println!("Operation contract {command} passed");
    Ok(())
}
#[cfg(not(feature = "operation-schemas"))]
fn main() {
    eprintln!("Enable --features operation-schemas");
    std::process::exit(1);
}
