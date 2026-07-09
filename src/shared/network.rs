use std::net::IpAddr;

/// Returns true for addresses that must not be contacted through an
/// administrator-supplied URL unless a feature has an explicit private-network
/// allow-list. This includes non-routable, documentation, transition, and
/// IPv4-embedded forms that are commonly missed by basic private-IP checks.
pub fn is_private_or_sensitive_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_or_sensitive_ipv4(ip.octets()),
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            if octets[..12] == [0; 12] || octets[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
            {
                return is_private_or_sensitive_ipv4([
                    octets[12], octets[13], octets[14], octets[15],
                ]);
            }

            let segments = ip.segments();
            let is_global_unicast = segments[0] & 0xe000 == 0x2000;
            let ietf_special = segments[0] == 0x2001 && segments[1] <= 0x01ff;
            let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
            let six_to_four = segments[0] == 0x2002;
            !is_global_unicast || ietf_special || documentation || six_to_four
        }
    }
}

fn is_private_or_sensitive_ipv4(octets: [u8; 4]) -> bool {
    matches!(octets[0], 0 | 10 | 127)
        || (octets[0] == 100 && octets[1] & 0xc0 == 0x40)
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && octets[1] & 0xf0 == 0x10)
        || (octets[0] == 192 && matches!(octets[1], 0 | 168)
            || octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19 | 51))
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_non_global_and_ipv4_embedded_addresses() {
        for address in [
            "0.1.2.3",
            "100.64.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::127.0.0.1",
            "2002:7f00:1::",
        ] {
            assert!(
                is_private_or_sensitive_ip(address.parse().unwrap()),
                "expected {address} to be blocked"
            );
        }
        assert!(!is_private_or_sensitive_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_or_sensitive_ip(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }
}
