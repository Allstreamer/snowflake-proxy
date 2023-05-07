use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

pub fn filter_local_from_sdp_offer(offer: &str) -> String {
    offer.lines().filter(|s| {
        if !s.starts_with("a=candidate") {
            return true;
        }
        let ip_addr = s.split_whitespace().nth(4);
        match ip_addr.map(|x| x.parse::<IpAddr>()) {
            Some(v) => {
                if let Ok(ip) = v {
                    (ip.is_loopback() || ip.is_unspecified() || ip.is_global_stable())
                }else {
                    false
                }
            },
            None => {
                return false
            }
        }
    }).collect::<Vec<&str>>().join("\r\n")
}

trait IpUtil {
    fn is_global_stable(&self) -> bool;
}

#[allow(unstable_name_collisions)]
impl IpUtil for IpAddr {
    fn is_global_stable(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_global(),
            IpAddr::V6(ip) => ip.is_global(),
        }
    }
}

trait IpUtil4 {
    fn is_global(&self) -> bool;
    fn is_shared(&self) -> bool;
    fn is_benchmarking(&self) -> bool;
    fn is_reserved(&self) -> bool;
}

#[allow(unstable_name_collisions)]
impl IpUtil4 for Ipv4Addr {
    fn is_global(&self) -> bool {
        !(self.octets()[0] == 0 // "This network"
            || self.is_private()
            || self.is_shared()
            || self.is_loopback()
            || self.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            ||(self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0)
            || self.is_documentation()
            || self.is_benchmarking()
            || self.is_reserved()
            || self.is_broadcast())
    }
    fn is_shared(&self) -> bool {
        self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
    }
    fn is_benchmarking(&self) -> bool {
        self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
    }
    fn is_reserved(&self) -> bool {
        self.octets()[0] & 240 == 240 && !self.is_broadcast()
    }
}

trait IpUtil6 {
    fn is_global(&self) -> bool;
    fn is_documentation(&self) -> bool;
    fn is_unique_local(&self) -> bool;
    fn is_unicast_link_local(&self) -> bool;
}

#[allow(unstable_name_collisions)]
impl IpUtil6 for Ipv6Addr {
    fn is_global(&self) -> bool {
        !(self.is_unspecified()
            || self.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
                ))
            || self.is_documentation()
            || self.is_unique_local()
            || self.is_unicast_link_local())
    }
    fn is_unique_local(&self) -> bool {
        (self.segments()[0] & 0xfe00) == 0xfc00
    }
    fn is_unicast_link_local(&self) -> bool {
        (self.segments()[0] & 0xffc0) == 0xfe80
    }
    fn is_documentation(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
    }
}