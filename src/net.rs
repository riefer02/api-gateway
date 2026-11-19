use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Which peers are allowed to speak for the client.
///
/// Empty means "trust nobody": the direct peer is the client. When the gateway
/// sits behind a load balancer, list that proxy's addresses and the client
/// address is taken from the forwarding chain, walking right to left and
/// skipping trusted hops.
#[derive(Clone, Debug, Default)]
pub(crate) struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    pub(crate) fn parse(entries: &[String]) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(entries.len());

        for entry in entries {
            let net = entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| format!("`{entry}` is not an IP or CIDR block"))?;

            nets.push(net);
        }

        Ok(Self { nets })
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        self.nets
            .iter()
            .any(|net| net.contains(&address))
    }

    /// Resolves the caller, honouring forwarding headers only from a trusted
    /// peer. A spoofed header from an untrusted peer is ignored.
    pub(crate) fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.contains(peer) {
            return peer;
        }

        // `X-Forwarded-For: client, proxy1, proxy2` — nearest hop is rightmost.
        for value in headers
            .get_all("x-forwarded-for")
            .iter()
        {
            let Ok(value) = value.to_str() else {
                continue;
            };

            for candidate in value.split(',').rev() {
                let candidate = candidate.trim();

                if let Ok(address) = candidate.parse::<IpAddr>()
                    && !self.contains(address)
                {
                    return address;
                }
            }
        }

        for name in ["x-real-ip", "true-client-ip"] {
            if let Some(value) = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                && let Ok(address) = value.trim().parse::<IpAddr>()
                && !self.contains(address)
            {
                return address;
            }
        }

        peer
    }
}

/// The resolved caller, attached once per request so the proxy can forward it
/// and the admin audit can record it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientIp(pub(crate) IpAddr);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn trusted(list: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(
            &list
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("valid proxies")
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn parses_addresses_and_blocks() {
        let proxies = trusted(&["127.0.0.1", "10.0.0.0/8"]);

        assert!(proxies.contains("127.0.0.1".parse().unwrap()));
        assert!(proxies.contains("10.1.2.3".parse().unwrap()));
        assert!(!proxies.contains("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn untrusted_peers_cannot_spoof_forwarding_headers() {
        let proxies = trusted(&[]);
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.9")]);

        let client = proxies.client_ip("198.51.100.4".parse().unwrap(), &forwarded);

        assert_eq!(
            client,
            "198.51.100.4"
                .parse::<IpAddr>()
                .unwrap()
        );
    }

    #[test]
    fn trusted_peers_yield_the_client() {
        let proxies = trusted(&["10.0.0.1"]);
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.9")]);

        let client = proxies.client_ip("10.0.0.1".parse().unwrap(), &forwarded);

        assert_eq!(client, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn the_chain_is_walked_from_the_nearest_hop() {
        let proxies = trusted(&["10.0.0.0/8"]);
        let forwarded = headers(&[("x-forwarded-for", "203.0.113.9, 10.0.0.5, 10.0.0.6")]);

        let client = proxies.client_ip("10.0.0.7".parse().unwrap(), &forwarded);

        assert_eq!(client, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn x_real_ip_is_the_fallback() {
        let proxies = trusted(&["10.0.0.1"]);
        let forwarded = headers(&[("x-real-ip", "203.0.113.9")]);

        let client = proxies.client_ip("10.0.0.1".parse().unwrap(), &forwarded);

        assert_eq!(client, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn garbage_forwarding_headers_fall_back_to_the_peer() {
        let proxies = trusted(&["10.0.0.1"]);
        let forwarded = headers(&[("x-forwarded-for", "not-an-ip, also-bad")]);

        let client = proxies.client_ip("10.0.0.1".parse().unwrap(), &forwarded);

        assert_eq!(client, "10.0.0.1".parse::<IpAddr>().unwrap());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The address we charge must never be one of our own proxies, or every
        /// caller behind the same proxy would share its bucket.
        #[test]
        fn the_client_is_never_a_trusted_hop(
            entries in prop::collection::vec(
                prop_oneof![
                    (0u8..=255).prop_map(|octet| format!("203.0.113.{octet}")),
                    (0u8..=255).prop_map(|octet| format!("10.0.0.{octet}")),
                ],
                1..6,
            ),
        ) {
            let proxies = TrustedProxies::parse(&["10.0.0.0/8".to_owned()]).expect("valid");
            let chain = entries.join(", ");
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", chain.parse().unwrap());

            let client = proxies.client_ip("10.0.0.1".parse().unwrap(), &headers);

            let all_trusted = entries
                .iter()
                .all(|entry| proxies.contains(entry.parse().unwrap()));

            prop_assert!(
                !proxies.contains(client) || all_trusted,
                "reported trusted address {:?} for chain {:?}",
                client,
                chain
            );
        }
    }
}

/// Which outbound addresses an upstream may resolve to.
///
/// The hostname allowlist decides *what the gateway is allowed to talk to*;
/// this decides *what that name is allowed to become*. Without it, an
/// allowlisted hostname that resolves to the instance metadata service, or to
/// the gateway's own admin listener, is reachable — the check validated a
/// string, not a socket.
///
/// Filtering happens when the address is resolved, and the filtered addresses
/// are what the client connects to, so there is no window between the check
/// and the connection for DNS to change its answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Egress {
    /// No address filtering. Correct only when upstreams legitimately live on
    /// loopback, which is a development shape, not a deployed one.
    AllowAll,
    /// Public, private and unique-local addresses are allowed; loopback,
    /// link-local, unspecified, multicast and the cloud metadata endpoints are
    /// not. The default: a VPC upstream works, `169.254.169.254` does not.
    #[default]
    DenyLinkLocal,
    /// Public unicast only. For deployments whose upstreams are all on the
    /// internet and which want to be unable to reach internal networks.
    DenyPrivate,
}

impl Egress {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "allow-all" => Some(Self::AllowAll),
            "deny-link-local" => Some(Self::DenyLinkLocal),
            "deny-private" => Some(Self::DenyPrivate),
            _ => None,
        }
    }

    pub(crate) fn allows(self, address: IpAddr) -> bool {
        match self {
            Self::AllowAll => true,
            Self::DenyLinkLocal => !is_local_or_metadata(address),
            Self::DenyPrivate => is_public(address),
        }
    }
}

/// `::ffff:169.254.169.254` must be judged as the IPv4 address it is, and the
/// deprecated IPv4-compatible `::a.b.c.d` form must not be a way around it.
/// `::1` is checked as IPv6 first: it is loopback, not mapped `0.0.0.1`.
fn is_local_or_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6 == METADATA_V6
            {
                return true;
            }

            v6.to_ipv4()
                .is_some_and(is_forbidden_v4)
        }
    }
}

fn is_forbidden_v4(address: std::net::Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_documentation()
        || is_public_cloud_metadata(address)
}

fn is_public(address: IpAddr) -> bool {
    if is_local_or_metadata(address) {
        return false;
    }

    match address {
        IpAddr::V4(v4) => !v4.is_private() && !is_carrier_grade_nat(v4),
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => !v4.is_private() && !is_carrier_grade_nat(v4),
            None => !v6.is_unique_local(),
        },
    }
}

/// Metadata endpoints that do not live in link-local and would otherwise be
/// reachable under `DenyLinkLocal`: Alibaba Cloud and Oracle Cloud.
fn is_public_cloud_metadata(address: std::net::Ipv4Addr) -> bool {
    address == std::net::Ipv4Addr::new(100, 100, 100, 200)
        || address == std::net::Ipv4Addr::new(192, 0, 0, 192)
}

/// 100.64.0.0/10, the carrier-grade NAT range. `Ipv4Addr::is_shared` is still
/// unstable, so the prefix is spelled out.
fn is_carrier_grade_nat(address: std::net::Ipv4Addr) -> bool {
    let octets = address.octets();

    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// The IPv6 instance metadata endpoint, which lives in the unique-local range
/// and would otherwise pass the `DenyLinkLocal` rule.
const METADATA_V6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);

/// Resolves a name and keeps only the addresses the policy allows.
///
/// A resolver rather than a one-time check: reqwest connects to exactly what
/// this returns, so a second lookup cannot return a different answer, and a
/// multi-address upstream keeps its failover instead of being pinned to one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EgressResolver {
    policy: Egress,
}

impl EgressResolver {
    pub(crate) fn new(policy: Egress) -> Self {
        Self { policy }
    }
}

impl reqwest::dns::Resolve for EgressResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let policy = self.policy;

        Box::pin(async move {
            let resolved = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("could not resolve `{host}`: {error}").into()
                })?;

            let allowed: Vec<std::net::SocketAddr> = resolved
                .filter(|socket| policy.allows(socket.ip()))
                .collect();

            if allowed.is_empty() {
                // Fail closed and say why, without echoing an address that may
                // be internal: the message names the host, not the target.
                return Err(format!(
                    "`{host}` resolves only to addresses the egress policy forbids"
                )
                .into());
            }

            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod egress_tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("valid address")
    }

    #[test]
    fn link_local_policy_blocks_metadata_and_loopback_but_not_internal_upstreams() {
        let policy = Egress::DenyLinkLocal;

        for blocked in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "100.100.100.200",
            "192.0.0.192",
            "fd00:ec2::254",
            "::127.0.0.1",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "fe80::1",
            "224.0.0.1",
        ] {
            assert!(!policy.allows(ip(blocked)), "{blocked} should be refused");
        }

        for allowed in [
            "10.1.2.3",
            "172.16.0.5",
            "192.168.1.10",
            "fd12:3456::1",
            "93.184.216.34",
        ] {
            assert!(policy.allows(ip(allowed)), "{allowed} should be allowed");
        }
    }

    #[test]
    fn private_policy_allows_public_unicast_only() {
        let policy = Egress::DenyPrivate;

        for blocked in ["10.0.0.1", "100.64.1.1", "fd00::1", "192.168.0.1"] {
            assert!(!policy.allows(ip(blocked)), "{blocked} should be refused");
        }

        assert!(policy.allows(ip("93.184.216.34")));
        assert!(policy.allows(ip("2606:2800:220:1::1")));
    }

    #[test]
    fn allow_all_filters_nothing() {
        let policy = Egress::AllowAll;

        assert!(policy.allows(ip("127.0.0.1")));
        assert!(policy.allows(ip("169.254.169.254")));
    }

    #[tokio::test]
    async fn the_resolver_drops_forbidden_addresses() {
        use reqwest::dns::{Name, Resolve};

        let name: Name = "localhost".parse().expect("valid name");

        let refused = EgressResolver::new(Egress::DenyLinkLocal)
            .resolve(name)
            .await;

        assert!(
            refused.is_err(),
            "localhost must not resolve under the default policy"
        );

        let name: Name = "localhost".parse().expect("valid name");
        let allowed = EgressResolver::new(Egress::AllowAll)
            .resolve(name)
            .await;

        assert!(allowed.is_ok(), "allow-all must still resolve localhost");
    }
}
