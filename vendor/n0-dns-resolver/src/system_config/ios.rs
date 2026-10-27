//! iOS uses SDK libresolv rather than unavailable macOS DynamicStore APIs.
use super::{Config, DnsProtocol, Nameserver};
use std::{io, net::SocketAddr};

fn parse_config(text: &str) -> io::Result<Config> {
    let invalid = || io::Error::other("Invalid iOS DNS configuration");
    let mut config = Config::default();
    for line in text.lines() {
        let (kind, value) = line.split_once(' ').ok_or_else(invalid)?;
        match kind {
            "server" if config.nameservers.len() < 3 => {
                let address: SocketAddr = value.parse().map_err(|_| invalid())?;
                if address.port() == 0 || address.ip().is_unspecified() {
                    return Err(invalid());
                }
                config
                    .nameservers
                    .push(Nameserver::new(address, DnsProtocol::Udp));
            }
            "search"
                if config.search_domains.len() < 7
                    && !value.is_empty()
                    && value.len() <= 253
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) =>
            {
                config.search_domains.push(value.to_owned());
            }
            "ndots" if config.ndots.is_none() => {
                config.ndots = Some(
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n <= 15)
                        .ok_or_else(invalid)?,
                );
            }
            _ => return Err(invalid()),
        }
    }
    if config.nameservers.is_empty() {
        return Err(invalid());
    }
    Ok(config)
}

#[cfg(target_os = "ios")]
pub(super) fn read_system_dns() -> io::Result<Config> {
    unsafe extern "C" {
        fn n0_read_ios_dns(out: *mut std::ffi::c_char, cap: usize) -> i32;
    }
    let mut bytes = [0u8; 16384];
    // SAFETY: the shim writes at most cap bytes and returns the byte count or -1.
    // It owns and destroys its resolver state; no pointer escapes the call.
    let size = unsafe { n0_read_ios_dns(bytes.as_mut_ptr().cast(), bytes.len()) };
    if size <= 0 || size as usize >= bytes.len() {
        return Err(io::Error::other("Cannot read iOS system DNS configuration"));
    }
    let text = std::str::from_utf8(&bytes[..size as usize])
        .map_err(|_| io::Error::other("Invalid iOS DNS text"))?;
    let mut config = parse_config(text)?;
    config.hosts = super::Hosts::from_system();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_system_ipv4_ipv6_scope_and_search_configuration() {
        let config = parse_config(
            "server 192.0.2.53:53\nserver [fe80::1%4]:5353\nsearch example.test\nndots 2\n",
        )
        .unwrap();
        assert_eq!(config.nameservers.len(), 2);
        assert_eq!(config.search_domains, ["example.test"]);
        assert_eq!(config.ndots, Some(2));
    }
    #[test]
    fn refuses_malformed_empty_and_over_budget_configuration() {
        for bad in [
            "",
            "server 0.0.0.0:53\n",
            "server 192.0.2.1:0\n",
            "server name:53\n",
            "server 192.0.2.1:53\nndots 16\n",
            "server 192.0.2.1:53\nsearch x y\n",
            "server 192.0.2.1:53\nndots 1\nndots 2\n",
        ] {
            assert!(parse_config(bad).is_err(), "{bad}");
        }
        assert!(parse_config(&"server 192.0.2.1:53\n".repeat(4)).is_err());
    }
}
