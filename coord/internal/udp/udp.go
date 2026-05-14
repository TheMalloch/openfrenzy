package udp

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"meshlink/coord/internal/db"
	"meshlink/coord/internal/proto"
)

// RegisteredPeer is an in-memory UDP peer entry.
type RegisteredPeer struct {
	PublicKey  [32]byte
	Endpoint   *net.UDPAddr
	ListenPort uint16
	LastSeen   time.Time
	VirtualIP  net.IP     // may be nil
	LanIP      net.IP     // may be nil
}

// PeerMap is the in-memory UDP peer registry.
type PeerMap struct {
	mu    sync.Mutex
	peers map[[32]byte]*RegisteredPeer
}

func NewPeerMap() *PeerMap {
	return &PeerMap{peers: make(map[[32]byte]*RegisteredPeer)}
}

func (m *PeerMap) Get(key [32]byte) (*RegisteredPeer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	return p, ok
}

func (m *PeerMap) Set(p *RegisteredPeer) {
	m.mu.Lock()
	m.peers[p.PublicKey] = p
	m.mu.Unlock()
}

func (m *PeerMap) Update(key [32]byte, fn func(*RegisteredPeer)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	if ok {
		fn(p)
	}
	return ok
}

// Snapshot returns a copy of all peers (caller owns the slice).
func (m *PeerMap) Snapshot() []*RegisteredPeer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*RegisteredPeer, 0, len(m.peers))
	for _, p := range m.peers {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

func (m *PeerMap) PruneStale(timeout time.Duration) int {
	cutoff := time.Now().Add(-timeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	before := len(m.peers)
	for k, p := range m.peers {
		if p.LastSeen.Before(cutoff) {
			delete(m.peers, k)
		}
	}
	return before - len(m.peers)
}

// Server is the UDP coordination server.
type Server struct {
	conn            *net.UDPConn
	db              *db.DB
	peers           *PeerMap
	staleSecs       int64
	cleanupInterval time.Duration
}

func NewServer(conn *net.UDPConn, database *db.DB, peers *PeerMap, staleSecs, cleanupIntervalSecs int64) *Server {
	return &Server{
		conn:            conn,
		db:              database,
		peers:           peers,
		staleSecs:       staleSecs,
		cleanupInterval: time.Duration(cleanupIntervalSecs) * time.Second,
	}
}

func (s *Server) Run() {
	slog.Info("UDP coordination server started")
	buf := make([]byte, 4096)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			slog.Warn("UDP recv error", "err", err)
			continue
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleMessage(pkt, normalizeAddr(src))
	}
}

// StaleChecker runs the periodic stale-node marking + broadcast loop.
func (s *Server) StaleChecker() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		count, err := s.db.MarkStaleNodes(s.staleSecs)
		if err != nil {
			slog.Warn("failed to mark stale nodes", "err", err)
			continue
		}
		if count > 0 {
			slog.Info("marked stale nodes", "count", count)
			s.BroadcastPeerList()
		}
		// Prune in-memory map too
		removed := s.peers.PruneStale(time.Duration(s.staleSecs) * time.Second)
		if removed > 0 {
			slog.Info("pruned stale UDP peers", "removed", removed)
		}
	}
}

// BroadcastPeerList sends a personalized PEER_LIST_RESP to every connected peer.
func (s *Server) BroadcastPeerList() {
	nodes, err := s.db.ListActiveNodes()
	if err != nil {
		slog.Warn("broadcast: failed to list active nodes", "err", err)
		return
	}
	snap := s.peers.Snapshot()
	for _, p := range snap {
		resp := s.buildPeerListResponse(p.PublicKey, nodes)
		if _, err := s.conn.WriteToUDP(resp, p.Endpoint); err != nil {
			slog.Warn("broadcast: send failed", "dst", p.Endpoint, "err", err)
		}
	}
	slog.Debug("broadcast peer list", "peers", len(snap))
}

func (s *Server) handleMessage(data []byte, src *net.UDPAddr) {
	if len(data) == 0 {
		return
	}
	switch data[0] {
	case proto.Register:
		s.handleRegister(data, src)
	case proto.PeerListReq:
		s.handlePeerListReq(data, src)
	case proto.Keepalive:
		s.handleKeepalive(data, src)
	default:
		slog.Debug("unknown UDP message type", "type", data[0], "src", src)
	}
}

func (s *Server) handleRegister(data []byte, src *net.UDPAddr) {
	if len(data) < 35 {
		slog.Debug("register too short", "src", src)
		return
	}
	var pubkey [32]byte
	copy(pubkey[:], data[1:33])
	listenPort := uint16(data[33])<<8 | uint16(data[34])

	lanIP := parseLanIPs(data, 35)

	_, alreadyKnown := s.peers.Get(pubkey)

	// Look up virtual IP from DB
	var vip net.IP
	if node, _ := s.db.GetNodeByPubkey(pubkey[:]); node != nil {
		host := stripCIDR(node.VirtualIP)
		vip = net.ParseIP(host).To4()
	}

	s.peers.Set(&RegisteredPeer{
		PublicKey:  pubkey,
		Endpoint:   src,
		ListenPort: listenPort,
		LastSeen:   time.Now(),
		VirtualIP:  vip,
		LanIP:      lanIP,
	})

	if !src.IP.IsLoopback() {
		ep := src.String()
		if ok, _ := s.db.UpdateEndpointByPubkey(pubkey[:], ep); ok {
			slog.Debug("persisted endpoint", "src", src)
		}
		if src.IP.To4() == nil {
			s.db.UpdateIPv6EndpointByPubkey(pubkey[:], ep)
		}
	}
	if lanIP != nil {
		lan := (&net.UDPAddr{IP: lanIP, Port: int(listenPort)}).String()
		s.db.UpdateLanEndpointByPubkey(pubkey[:], &lan)
	}

	if !alreadyKnown {
		slog.Info("new peer registered", "src", src, "listen_port", listenPort)
		s.BroadcastPeerList()
	} else {
		slog.Debug("peer re-registered", "src", src)
	}
}

func (s *Server) handlePeerListReq(data []byte, src *net.UDPAddr) {
	if len(data) < 33 {
		slog.Debug("peer list req too short", "src", src)
		return
	}
	var requesterKey [32]byte
	copy(requesterKey[:], data[1:33])

	nodes, err := s.db.ListActiveNodes()
	if err != nil {
		slog.Warn("peer list req: db error", "err", err)
		return
	}
	resp := s.buildPeerListResponse(requesterKey, nodes)
	count := uint16(resp[1])<<8 | uint16(resp[2])
	slog.Debug("sending peer list", "src", src, "count", count)
	s.conn.WriteToUDP(resp, src)
}

func (s *Server) handleKeepalive(data []byte, src *net.UDPAddr) {
	if len(data) < 33 {
		return
	}
	var pubkey [32]byte
	copy(pubkey[:], data[1:33])

	lanIP := parseLanIPs(data, 33)

	updated := s.peers.Update(pubkey, func(p *RegisteredPeer) {
		p.LastSeen = time.Now()
		p.Endpoint = src
		if lanIP != nil {
			p.LanIP = lanIP
		}
		slog.Debug("keepalive", "src", src)
	})

	if !updated {
		// Server restart: re-register from keepalive
		var vip net.IP
		if node, _ := s.db.GetNodeByPubkey(pubkey[:]); node != nil {
			vip = net.ParseIP(stripCIDR(node.VirtualIP)).To4()
		}
		s.peers.Set(&RegisteredPeer{
			PublicKey:  pubkey,
			Endpoint:   src,
			ListenPort: uint16(src.Port),
			LastSeen:   time.Now(),
			VirtualIP:  vip,
			LanIP:      lanIP,
		})
		slog.Info("re-registered peer from keepalive", "src", src)
		s.BroadcastPeerList()
	}

	// Persist endpoint
	s.db.UpdateEndpointByPubkey(pubkey[:], src.String())

	if lanIP != nil {
		listenPort := uint16(src.Port)
		if p, ok := s.peers.Get(pubkey); ok {
			listenPort = p.ListenPort
		}
		lan := (&net.UDPAddr{IP: lanIP, Port: int(listenPort)}).String()
		s.db.UpdateLanEndpointByPubkey(pubkey[:], &lan)
	}
}

// buildPeerListResponse builds a PEER_LIST_RESP excluding the requester.
func (s *Server) buildPeerListResponse(requesterKey [32]byte, nodes []*db.NodeRecord) []byte {
	var filtered []*db.NodeRecord
	for _, n := range nodes {
		if len(n.PublicKey) == 32 {
			var k [32]byte
			copy(k[:], n.PublicKey)
			if k != requesterKey {
				filtered = append(filtered, n)
			}
		}
	}

	count := len(filtered)
	if count > 0xffff {
		count = 0xffff
	}

	resp := make([]byte, 0, 3+count*(32+4+1+16+2+4+2))
	resp = append(resp, proto.PeerListResp)
	resp = append(resp, byte(count>>8), byte(count))

	snap := s.peers.Snapshot()
	peerByKey := make(map[[32]byte]*RegisteredPeer, len(snap))
	for _, p := range snap {
		peerByKey[p.PublicKey] = p
	}

	for _, node := range filtered[:count] {
		resp = append(resp, node.PublicKey...)

		// Virtual IP (4 bytes)
		vipStr := stripCIDR(node.VirtualIP)
		vip := net.ParseIP(vipStr).To4()
		if vip == nil {
			vip = []byte{0, 0, 0, 0}
		}
		resp = append(resp, vip...)

		// Endpoint: prefer live UDP, fall back to DB
		var k [32]byte
		copy(k[:], node.PublicKey)
		var ep *net.UDPAddr
		if live, ok := peerByKey[k]; ok {
			ep = live.Endpoint
		} else if node.Endpoint.Valid {
			ep, _ = net.ResolveUDPAddr("udp", node.Endpoint.String)
		}

		if ep != nil {
			ip4 := ep.IP.To4()
			if ip4 != nil {
				resp = append(resp, 0x04)
				resp = append(resp, ip4...)
			} else {
				resp = append(resp, 0x06)
				resp = append(resp, ep.IP.To16()...)
			}
			resp = append(resp, byte(ep.Port>>8), byte(ep.Port))
		} else {
			resp = append(resp, 0x04, 0, 0, 0, 0, 0, 0)
		}

		// LAN IP + LAN port
		var lanIP net.IP
		var lanPort uint16
		if live, ok := peerByKey[k]; ok && live.LanIP != nil {
			lanIP = live.LanIP
			lanPort = live.ListenPort
		} else if node.LanEndpoint.Valid {
			laddr, _ := net.ResolveUDPAddr("udp", node.LanEndpoint.String)
			if laddr != nil {
				lanIP = laddr.IP.To4()
				lanPort = uint16(laddr.Port)
			}
		}
		if lanIP == nil {
			lanIP = []byte{0, 0, 0, 0}
		}
		if len(lanIP) < 4 {
			lanIP = []byte{0, 0, 0, 0}
		}
		resp = append(resp, lanIP[:4]...)
		resp = append(resp, byte(lanPort>>8), byte(lanPort))
	}

	return resp
}

// parseLanIPs parses the optional LAN IPs appended to REGISTER/KEEPALIVE.
// Format: [count:1][ip_0:4]...[ip_n:4] — returns first usable non-loopback IPv4.
func parseLanIPs(data []byte, offset int) net.IP {
	if offset >= len(data) {
		return nil
	}
	count := int(data[offset])
	pos := offset + 1
	for i := 0; i < count; i++ {
		if pos+4 > len(data) {
			break
		}
		ip := net.IP(data[pos : pos+4]).To4()
		pos += 4
		if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.Equal(net.IPv4zero) {
			return ip
		}
	}
	return nil
}

func normalizeAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return addr
	}
	if v4 := addr.IP.To4(); v4 != nil {
		return &net.UDPAddr{IP: v4, Port: addr.Port}
	}
	return addr
}

func stripCIDR(s string) string {
	for i, c := range s {
		if c == '/' {
			return s[:i]
		}
	}
	return s
}
