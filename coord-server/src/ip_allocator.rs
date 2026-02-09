use anyhow::{Context, Result};
use std::net::Ipv4Addr;

/// Allocates virtual IPs from a configured CIDR network.
#[derive(Clone)]
pub struct IpAllocator {
    /// The network address (e.g., 10.0.0.0)
    network: Ipv4Addr,
    /// The prefix length (e.g., 24)
    prefix_len: u8,
}

impl IpAllocator {
    /// Create a new allocator from a CIDR string like "10.0.0.0/24".
    pub fn new(cidr: &str) -> Result<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("invalid CIDR format: {cidr}");
        }
        let network: Ipv4Addr = parts[0].parse().context("parsing network address")?;
        let prefix_len: u8 = parts[1].parse().context("parsing prefix length")?;
        if prefix_len > 30 {
            anyhow::bail!("prefix length must be <= 30, got {prefix_len}");
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Allocate the next free IP address, given a list of already-allocated IPs.
    /// Skips the network address (.0) and broadcast address (.255 for /24).
    pub fn allocate(&self, allocated: &[String]) -> Result<String> {
        let net_u32 = u32::from(self.network);
        let host_bits = 32 - self.prefix_len as u32;
        let host_count = (1u32 << host_bits) - 2; // exclude network and broadcast

        let allocated_addrs: Vec<Ipv4Addr> = allocated
            .iter()
            .filter_map(|ip_str| {
                // Handle "10.0.0.1/24" or "10.0.0.1" formats
                let addr_part = ip_str.split('/').next().unwrap_or(ip_str);
                addr_part.parse().ok()
            })
            .collect();

        for i in 1..=host_count {
            let candidate = Ipv4Addr::from(net_u32 + i);
            if !allocated_addrs.contains(&candidate) {
                let ip_with_prefix = format!("{}/{}", candidate, self.prefix_len);
                return Ok(ip_with_prefix);
            }
        }

        anyhow::bail!("IP pool exhausted — no free addresses in {}/{}", self.network, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_first_ip() {
        let alloc = IpAllocator::new("10.0.0.0/24").unwrap();
        let ip = alloc.allocate(&[]).unwrap();
        assert_eq!(ip, "10.0.0.1/24");
    }

    #[test]
    fn test_allocate_skips_used() {
        let alloc = IpAllocator::new("10.0.0.0/24").unwrap();
        let used = vec!["10.0.0.1/24".to_string()];
        let ip = alloc.allocate(&used).unwrap();
        assert_eq!(ip, "10.0.0.2/24");
    }

    #[test]
    fn test_allocate_skips_multiple_used() {
        let alloc = IpAllocator::new("10.0.0.0/24").unwrap();
        let used = vec![
            "10.0.0.1/24".to_string(),
            "10.0.0.2/24".to_string(),
            "10.0.0.3/24".to_string(),
        ];
        let ip = alloc.allocate(&used).unwrap();
        assert_eq!(ip, "10.0.0.4/24");
    }

    #[test]
    fn test_allocate_exhaustion() {
        let alloc = IpAllocator::new("10.0.0.0/30").unwrap();
        // /30 has 2 usable hosts: .1 and .2
        let used = vec!["10.0.0.1/30".to_string(), "10.0.0.2/30".to_string()];
        let result = alloc.allocate(&used);
        assert!(result.is_err());
    }

    #[test]
    fn test_allocate_handles_bare_ip() {
        let alloc = IpAllocator::new("10.0.0.0/24").unwrap();
        let used = vec!["10.0.0.1".to_string()];
        let ip = alloc.allocate(&used).unwrap();
        assert_eq!(ip, "10.0.0.2/24");
    }
}
