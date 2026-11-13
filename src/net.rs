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
