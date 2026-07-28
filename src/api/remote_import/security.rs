use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};

use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::{
    api::api_response::ApiError,
    config::{RemoteImportSecurityConfig, normalize_remote_import_host},
};

const MAX_CONCURRENT_REMOTE_DNS_LOOKUPS: usize = 8;
const MAX_RESOLVED_REMOTE_ADDRESSES: usize = 64;
static REMOTE_DNS_LOOKUPS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_REMOTE_DNS_LOOKUPS));

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteEndpointRequest {
    pub host: String,
    pub port: Option<u16>,
    pub tls: bool,
}

impl Default for RemoteEndpointRequest {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: None,
            tls: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRemoteEndpoint {
    pub host: String,
    pub port: u16,
    pub addresses: Vec<SocketAddr>,
    pub tls: bool,
}

impl ResolvedRemoteEndpoint {
    /// Docker/Podman `HostConfig.ExtraHosts` entries that pin the validated
    /// hostname to the exact addresses classified by this module.
    ///
    /// Literal IP requests need no hosts-file entry. TLS clients must continue
    /// to use `host`, rather than a resolved address, so certificate identity
    /// verification remains bound to the requested name.
    pub fn helper_extra_hosts(&self) -> Vec<String> {
        if self.host.parse::<IpAddr>().is_ok() {
            return Vec::new();
        }
        self.addresses
            .iter()
            .map(|address| match address.ip() {
                IpAddr::V4(ip) => format!("{}:{ip}", self.host),
                IpAddr::V6(ip) => format!("{}:[{ip}]", self.host),
            })
            .collect()
    }
}

pub async fn resolve_endpoint(
    request: &RemoteEndpointRequest,
    default_port: u16,
    security: &RemoteImportSecurityConfig,
) -> Result<ResolvedRemoteEndpoint, ApiError> {
    resolve_endpoint_with(
        request.clone(),
        default_port,
        security,
        |host, port| async move {
            let _permit = REMOTE_DNS_LOOKUPS
                .acquire()
                .await
                .map_err(|_| io::Error::other("remote DNS limiter closed"))?;
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addresses| addresses.collect())
        },
    )
    .await
}

async fn resolve_endpoint_with<R, F>(
    request: RemoteEndpointRequest,
    default_port: u16,
    security: &RemoteImportSecurityConfig,
    resolver: R,
) -> Result<ResolvedRemoteEndpoint, ApiError>
where
    R: FnOnce(String, u16) -> F,
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    if !security.enabled {
        return Err(ApiError::BadRequest(
            "remote credential imports are disabled by node policy".to_string(),
        ));
    }
    if !request.tls && !security.allow_plaintext {
        return Err(ApiError::BadRequest(
            "remote imports require TLS unless security.remote_import.allow_plaintext is enabled"
                .to_string(),
        ));
    }

    let host = normalize_remote_import_host(&request.host).ok_or_else(|| {
        ApiError::BadRequest(
            "remote source host must be a valid host name or IP address without a URL, path, or port"
                .to_string(),
        )
    })?;
    let port = request.port.unwrap_or(default_port);
    if port == 0 {
        return Err(ApiError::BadRequest(
            "remote source port must be greater than zero".to_string(),
        ));
    }

    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        let resolution = resolver(host.clone(), port);
        tokio::time::timeout(
            Duration::from_secs(security.connect_timeout_seconds),
            resolution,
        )
        .await
        .map_err(|_| {
            ApiError::BadRequest(format!(
                "remote source host {host} did not resolve before the configured timeout"
            ))
        })?
        .map_err(|_| {
            ApiError::BadRequest(format!("remote source host {host} could not be resolved"))
        })?
        .into_iter()
        .map(|address| SocketAddr::new(address.ip(), port))
        .collect()
    };

    let addresses = validate_resolved_addresses(&host, addresses, security)?;
    Ok(ResolvedRemoteEndpoint {
        host,
        port,
        addresses,
        tls: request.tls,
    })
}

fn validate_resolved_addresses(
    host: &str,
    mut addresses: Vec<SocketAddr>,
    security: &RemoteImportSecurityConfig,
) -> Result<Vec<SocketAddr>, ApiError> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "remote source host {host} did not resolve to an address"
        )));
    }
    if addresses.len() > MAX_RESOLVED_REMOTE_ADDRESSES {
        return Err(ApiError::BadRequest(format!(
            "remote source host {host} resolved to more than {MAX_RESOLVED_REMOTE_ADDRESSES} addresses"
        )));
    }

    let private_allowed = security
        .allowed_private_hosts
        .iter()
        .filter_map(|allowed| normalize_remote_import_host(allowed))
        .any(|allowed| allowed.eq_ignore_ascii_case(host));
    let mut saw_public = false;
    let mut saw_private = false;

    for address in &addresses {
        match classify_address(address.ip()) {
            AddressClass::Public => saw_public = true,
            AddressClass::Private => {
                saw_private = true;
                if !private_allowed {
                    return Err(ApiError::BadRequest(format!(
                        "remote source host {host} resolves to a private address and is not present in security.remote_import.allowed_private_hosts"
                    )));
                }
            }
            AddressClass::Forbidden => {
                return Err(ApiError::BadRequest(format!(
                    "remote source host {host} resolves to a loopback, link-local, metadata, multicast, documentation, or reserved address"
                )));
            }
        }
    }

    if saw_public && saw_private {
        return Err(ApiError::BadRequest(format!(
            "remote source host {host} resolves to a mix of public and private addresses"
        )));
    }
    Ok(addresses)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    Public,
    Private,
    Forbidden,
}

fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) if address.to_ipv4_mapped().is_some() => AddressClass::Forbidden,
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressClass {
    // Some cloud control-plane endpoints use otherwise routable-looking
    // addresses rather than the usual IPv4 link-local metadata address.
    if address == Ipv4Addr::new(100, 100, 100, 200) || address == Ipv4Addr::new(168, 63, 129, 16) {
        return AddressClass::Forbidden;
    }

    if in_ipv4_prefix(address, [10, 0, 0, 0], 8)
        || in_ipv4_prefix(address, [172, 16, 0, 0], 12)
        || in_ipv4_prefix(address, [192, 168, 0, 0], 16)
        || in_ipv4_prefix(address, [100, 64, 0, 0], 10)
    {
        return AddressClass::Private;
    }

    // Reject non-forwardable and IANA special-purpose ranges even when some
    // individual anycast assignments inside them are globally reachable.
    if in_ipv4_prefix(address, [0, 0, 0, 0], 8)
        || in_ipv4_prefix(address, [127, 0, 0, 0], 8)
        || in_ipv4_prefix(address, [169, 254, 0, 0], 16)
        || in_ipv4_prefix(address, [192, 0, 0, 0], 24)
        || in_ipv4_prefix(address, [192, 0, 2, 0], 24)
        || in_ipv4_prefix(address, [192, 31, 196, 0], 24)
        || in_ipv4_prefix(address, [192, 52, 193, 0], 24)
        || in_ipv4_prefix(address, [192, 88, 99, 0], 24)
        || in_ipv4_prefix(address, [192, 175, 48, 0], 24)
        || in_ipv4_prefix(address, [198, 18, 0, 0], 15)
        || in_ipv4_prefix(address, [198, 51, 100, 0], 24)
        || in_ipv4_prefix(address, [203, 0, 113, 0], 24)
        || in_ipv4_prefix(address, [224, 0, 0, 0], 4)
        || in_ipv4_prefix(address, [240, 0, 0, 0], 4)
    {
        AddressClass::Forbidden
    } else {
        AddressClass::Public
    }
}

fn in_ipv4_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u32) -> bool {
    let address = u32::from(address);
    let network = u32::from(Ipv4Addr::from(network));
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    address & mask == network & mask
}

fn classify_ipv6(address: Ipv6Addr) -> AddressClass {
    // AWS IMDS has an IPv6 ULA endpoint. It must remain blocked even if an
    // operator allowlists a hostname that resolves into private address space.
    if address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) {
        return AddressClass::Forbidden;
    }

    let segments = address.segments();
    if segments[0] & 0xfe00 == 0xfc00 {
        return AddressClass::Private;
    }

    let first_byte = address.octets()[0];
    // Keep non-forwardable and IANA special-purpose ranges out of helpers.
    let forbidden = address.is_unspecified()
        || address.is_loopback()
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        || first_byte == 0xff
        || first_byte == 0
        || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
        || in_ipv6_prefix(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        || in_ipv6_prefix(address, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        || in_ipv6_prefix(
            address,
            Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0),
            48,
        )
        || in_ipv6_prefix(address, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
        || segments[0] & 0xe000 != 0x2000;

    if forbidden {
        AddressClass::Forbidden
    } else {
        AddressClass::Public
    }
}

fn in_ipv6_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let address = u128::from(address);
    let network = u128::from(network);
    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
    address & mask == network & mask
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;

    fn secure_config() -> RemoteImportSecurityConfig {
        RemoteImportSecurityConfig::default()
    }

    fn endpoint(host: &str) -> RemoteEndpointRequest {
        RemoteEndpointRequest {
            host: host.to_string(),
            port: None,
            tls: true,
        }
    }

    async fn resolve_with_addresses(
        host: &str,
        addresses: &[IpAddr],
        security: &RemoteImportSecurityConfig,
    ) -> Result<ResolvedRemoteEndpoint, ApiError> {
        let addresses = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, 5432))
            .collect::<Vec<_>>();
        resolve_endpoint_with(endpoint(host), 5432, security, move |_, _| async move {
            Ok(addresses)
        })
        .await
    }

    #[test]
    fn endpoint_request_defaults_to_tls() {
        let request: RemoteEndpointRequest =
            serde_json::from_value(serde_json::json!({"host": "db.example.com"})).unwrap();

        assert_eq!(request.port, None);
        assert!(request.tls);
    }

    #[tokio::test]
    async fn resolves_and_pins_public_addresses() {
        let resolved = resolve_with_addresses(
            "DB.Example.COM.",
            &[
                "2001:4860:4860::8888".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ],
            &secure_config(),
        )
        .await
        .unwrap();

        assert_eq!(resolved.host, "db.example.com");
        assert_eq!(resolved.port, 5432);
        assert_eq!(resolved.addresses.len(), 2);
        assert_eq!(
            resolved.helper_extra_hosts(),
            vec![
                "db.example.com:8.8.8.8",
                "db.example.com:[2001:4860:4860::8888]",
            ]
        );
    }

    #[tokio::test]
    async fn literal_ip_does_not_call_dns_or_create_extra_hosts() {
        let resolved = resolve_endpoint_with(
            RemoteEndpointRequest {
                host: "8.8.8.8".to_string(),
                port: Some(15432),
                tls: true,
            },
            5432,
            &secure_config(),
            |_, _| async { panic!("literal IP must bypass DNS") },
        )
        .await
        .unwrap();

        assert_eq!(resolved.addresses, vec!["8.8.8.8:15432".parse().unwrap()]);
        assert!(resolved.helper_extra_hosts().is_empty());
    }

    #[tokio::test]
    async fn remote_import_must_be_enabled() {
        let mut security = secure_config();
        security.enabled = false;

        let error =
            resolve_with_addresses("db.example.com", &["8.8.8.8".parse().unwrap()], &security)
                .await
                .unwrap_err();

        assert!(error.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn plaintext_requires_explicit_node_policy() {
        let request = RemoteEndpointRequest {
            host: "8.8.8.8".to_string(),
            port: None,
            tls: false,
        };
        let error = resolve_endpoint_with(request.clone(), 5432, &secure_config(), |_, _| async {
            panic!("policy rejection must happen before DNS")
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("require TLS"));

        let mut security = secure_config();
        security.allow_plaintext = true;
        let resolved = resolve_endpoint_with(request, 5432, &security, |_, _| async {
            panic!("literal IP must bypass DNS")
        })
        .await
        .unwrap();
        assert!(!resolved.tls);
    }

    #[tokio::test]
    async fn rejects_invalid_or_ambiguous_hosts_and_zero_ports() {
        for host in [
            "",
            "https://db.example.com",
            "user@db.example.com",
            "db.example.com/path",
            "db_name.example.com",
            "127.1",
            "2130706433",
            "0x7f.0.0.1",
        ] {
            let error =
                resolve_endpoint_with(endpoint(host), 5432, &secure_config(), |_, _| async {
                    panic!("invalid host must be rejected before DNS")
                })
                .await
                .unwrap_err();
            assert!(error.to_string().contains("valid host name"), "{host}");
        }

        let request = RemoteEndpointRequest {
            host: "8.8.8.8".to_string(),
            port: Some(0),
            tls: true,
        };
        let error = resolve_endpoint_with(request, 5432, &secure_config(), |_, _| async {
            panic!("invalid port must be rejected before DNS")
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("port"));
    }

    #[tokio::test]
    async fn rejects_empty_failed_and_timed_out_resolution() {
        let empty = resolve_with_addresses("db.example.com", &[], &secure_config())
            .await
            .unwrap_err();
        assert!(empty.to_string().contains("did not resolve to an address"));

        let failure = resolve_endpoint_with(
            endpoint("db.example.com"),
            5432,
            &secure_config(),
            |_, _| async { Err(io::Error::other("resolver detail")) },
        )
        .await
        .unwrap_err();
        assert!(failure.to_string().contains("could not be resolved"));
        assert!(!failure.to_string().contains("resolver detail"));

        let mut security = secure_config();
        security.connect_timeout_seconds = 0;
        let timeout =
            resolve_endpoint_with(endpoint("db.example.com"), 5432, &security, |_, _| async {
                pending::<io::Result<Vec<SocketAddr>>>().await
            })
            .await
            .unwrap_err();
        assert!(timeout.to_string().contains("configured timeout"));
    }

    #[tokio::test]
    async fn rejects_excessive_dns_answer_sets() {
        let addresses = (1..=MAX_RESOLVED_REMOTE_ADDRESSES + 1)
            .map(|suffix| IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, suffix as u16)))
            .collect::<Vec<_>>();

        let error = resolve_with_addresses("many.example", &addresses, &secure_config())
            .await
            .unwrap_err();

        assert!(error.to_string().contains("more than 64 addresses"));
    }

    #[tokio::test]
    async fn rejects_private_addresses_without_exact_allowlist_match() {
        for address in [
            "10.0.0.1",
            "172.16.10.2",
            "192.168.1.5",
            "100.64.0.1",
            "fd00::1234",
        ] {
            let error = resolve_with_addresses(
                "db.internal.example",
                &[address.parse().unwrap()],
                &secure_config(),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("private address"), "{address}");
        }
    }

    #[tokio::test]
    async fn exact_allowlist_match_accepts_private_addresses() {
        let mut security = secure_config();
        security.allowed_private_hosts = vec!["DB.Internal.Example.".to_string()];

        let resolved = resolve_with_addresses(
            "db.internal.example",
            &["10.0.0.1".parse().unwrap(), "fd00::1234".parse().unwrap()],
            &security,
        )
        .await
        .unwrap();

        assert_eq!(resolved.addresses.len(), 2);
    }

    #[tokio::test]
    async fn allowlist_never_overrides_always_forbidden_ranges() {
        let mut security = secure_config();
        security.allowed_private_hosts = vec!["blocked.internal".to_string()];
        for address in [
            "0.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "168.63.129.16",
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fec0::1",
            "fd00:ec2::254",
            "2001:db8::1",
            "2002::1",
            "2620:4f:8000::1",
            "3fff::1",
            "ff02::1",
        ] {
            let error =
                resolve_with_addresses("blocked.internal", &[address.parse().unwrap()], &security)
                    .await
                    .unwrap_err();
            assert!(
                error.to_string().contains("reserved address"),
                "{address}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_is_always_rejected() {
        let mut security = secure_config();
        security.allowed_private_hosts = vec!["blocked.internal".to_string()];

        for (host, address, policy) in [
            ("blocked.internal", "::ffff:127.0.0.1", security.clone()),
            ("public.example", "::ffff:8.8.8.8", secure_config()),
        ] {
            let error = resolve_with_addresses(host, &[address.parse().unwrap()], &policy)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("reserved address"), "{address}");
        }
    }

    #[tokio::test]
    async fn rejects_mixed_public_and_private_dns_answers_even_when_allowlisted() {
        let mut security = secure_config();
        security.allowed_private_hosts = vec!["mixed.example".to_string()];

        let error = resolve_with_addresses(
            "mixed.example",
            &["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()],
            &security,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("mix of public and private"));
    }
}
