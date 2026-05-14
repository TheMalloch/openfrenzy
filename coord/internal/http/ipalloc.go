package http

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type ipAllocator struct {
	network   net.IP // host byte order as uint32
	prefixLen int
	networkU32 uint32
	mask       uint32
}

func newIPAllocator(cidr string) (*ipAllocator, error) {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid CIDR: %q", cidr)
	}
	ip := net.ParseIP(parts[0]).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %q", parts[0])
	}
	var prefixLen int
	if _, err := fmt.Sscanf(parts[1], "%d", &prefixLen); err != nil || prefixLen < 0 || prefixLen > 30 {
		return nil, fmt.Errorf("invalid prefix length: %q (must be 0-30)", parts[1])
	}
	netU32 := binary.BigEndian.Uint32(ip)
	mask := ^((uint32(1) << (32 - prefixLen)) - 1)
	return &ipAllocator{network: ip, prefixLen: prefixLen, networkU32: netU32, mask: mask}, nil
}

func (a *ipAllocator) allocate(allocated []string) (string, error) {
	used := make(map[uint32]bool, len(allocated))
	for _, s := range allocated {
		host := strings.SplitN(s, "/", 2)[0]
		if ip := net.ParseIP(host).To4(); ip != nil {
			used[binary.BigEndian.Uint32(ip)] = true
		}
	}
	hostBits := uint32(32 - a.prefixLen)
	hostCount := (uint32(1) << hostBits) - 2
	for i := uint32(1); i <= hostCount; i++ {
		candidate := a.networkU32 + i
		if !used[candidate] {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, candidate)
			return fmt.Sprintf("%s/%d", ip.String(), a.prefixLen), nil
		}
	}
	return "", fmt.Errorf("IP pool exhausted")
}
