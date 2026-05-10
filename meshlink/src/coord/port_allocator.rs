use anyhow::Result;

/// Allocates non-overlapping port-range blocks for mesh peers.
///
/// Each peer gets a block of `block_size` consecutive ports starting at
/// `base + n * block_size` where `n` is the first slot not already allocated.
#[derive(Clone)]
pub struct PortAllocator {
    base: u16,
    block_size: u16,
}

impl PortAllocator {
    pub fn new(base: u16, block_size: u16) -> Self {
        Self { base, block_size }
    }

    /// Allocate the first free port-range block not in `allocated_starts`.
    /// Returns `(range_start, block_size)`.
    pub fn allocate(&self, allocated_starts: &[i32]) -> Result<(u16, u16)> {
        for slot in 0u32..10_000 {
            let candidate = self.base as u32 + slot * self.block_size as u32;
            if candidate > u16::MAX as u32 {
                break;
            }
            let candidate = candidate as u16;
            if !allocated_starts.contains(&(candidate as i32)) {
                return Ok((candidate, self.block_size));
            }
        }
        anyhow::bail!("port range pool exhausted (base={}, block_size={})", self.base, self.block_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_first_slot() {
        let a = PortAllocator::new(9000, 100);
        let (start, size) = a.allocate(&[]).unwrap();
        assert_eq!(start, 9000);
        assert_eq!(size, 100);
    }

    #[test]
    fn test_allocate_skips_used() {
        let a = PortAllocator::new(9000, 100);
        let (start, _) = a.allocate(&[9000]).unwrap();
        assert_eq!(start, 9100);
    }

    #[test]
    fn test_allocate_skips_multiple() {
        let a = PortAllocator::new(9000, 100);
        let (start, _) = a.allocate(&[9000, 9100, 9200]).unwrap();
        assert_eq!(start, 9300);
    }
}
