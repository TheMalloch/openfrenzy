package http

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
	"meshlink/coord/internal/db"
	udppkg "meshlink/coord/internal/udp"
)

// Server is the HTTP coordination API server.
type Server struct {
	db              *db.DB
	alloc           *ipAllocator
	coordAddr       string
	adminToken      string
	defaultPort     int
	updatesDir      string
	pasetoKey       paseto.V4SymmetricKey
	udpServer       *udppkg.Server
	peerMap         *udppkg.PeerMap
}

type Config struct {
	Port        int
	BindAddr    string
	DB          *db.DB
	MeshCIDR    string
	CoordAddr   string
	AdminToken  string
	DefaultPort int
	UpdatesDir  string
	PasetoKey   paseto.V4SymmetricKey
	UDPServer   *udppkg.Server
	PeerMap     *udppkg.PeerMap
}

func NewServer(cfg Config) (*Server, error) {
	alloc, err := newIPAllocator(cfg.MeshCIDR)
	if err != nil {
		return nil, fmt.Errorf("ip allocator: %w", err)
	}
	if err := os.MkdirAll(cfg.UpdatesDir, 0o755); err != nil {
		return nil, fmt.Errorf("updates dir: %w", err)
	}
	return &Server{
		db:          cfg.DB,
		alloc:       alloc,
		coordAddr:   cfg.CoordAddr,
		adminToken:  cfg.AdminToken,
		defaultPort: cfg.DefaultPort,
		updatesDir:  cfg.UpdatesDir,
		pasetoKey:   cfg.PasetoKey,
		udpServer:   cfg.UDPServer,
		peerMap:     cfg.PeerMap,
	}, nil
}

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/register", s.handleRegister)
	mux.HandleFunc("PATCH /api/v1/node/token", s.handleRotateToken)
	mux.HandleFunc("POST /api/v1/update", s.handlePublishUpdate)
	mux.HandleFunc("GET /api/v1/update/latest", s.handleGetLatestUpdate)
	mux.HandleFunc("GET /api/v1/update/latest/binary", s.handleDownloadLatestBinary)
	mux.HandleFunc("GET /api/v1/admin/updates", s.handleListUpdates)

	slog.Info("HTTP API server starting", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

// --- Auth helpers ---

func (s *Server) extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	return strings.TrimPrefix(auth, "Bearer ")
}

func (s *Server) isAdmin(r *http.Request) bool {
	return s.adminToken != "" && s.extractToken(r) == s.adminToken
}

func (s *Server) resolveCaller(r *http.Request) (string, bool) {
	tok := s.extractToken(r)
	if tok == "" {
		return "", false
	}
	if s.adminToken != "" && tok == s.adminToken {
		return "admin", true
	}
	nodeID, ok, _ := s.db.ValidatePeerToken(tok)
	return nodeID, ok
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- PASETO invite helpers ---

type inviteClaims struct {
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	CreatedAt time.Time `json:"created_at"`
}

// GenerateInviteToken creates a PASETO v4 local token encoding invite metadata.
func (s *Server) GenerateInviteToken(maxUses int, expiresAt time.Time) (string, error) {
	tok := paseto.NewToken()
	tok.SetExpiration(expiresAt)
	tok.SetIssuedAt(time.Now())
	tok.SetNotBefore(time.Now())
	tok.Set("max_uses", maxUses)
	return tok.V4Encrypt(s.pasetoKey, nil), nil
}

func (s *Server) validateInvite(code string) error {
	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now()))
	_, err := parser.ParseV4Local(s.pasetoKey, code, nil)
	if err != nil {
		return fmt.Errorf("invalid invite: %w", err)
	}
	return nil
}

// --- Handlers ---

type registerRequest struct {
	InviteCode string `json:"invite_code"`
	NodeName   string `json:"node_name,omitempty"`
}

type registerResponse struct {
	NodeID     string `json:"node_id"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	VirtualIP  string `json:"virtual_ip"`
	ConfigTOML string `json:"config_toml"`
	AuthToken  string `json:"auth_token"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.validateInvite(req.InviteCode); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired invite code")
		return
	}

	// Generate X25519 keypair
	privKey, pubKey, err := generateKeypair()
	if err != nil {
		slog.Error("keypair generation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Allocate IP
	allocatedIPs, err := s.db.AllocatedIPs()
	if err != nil {
		slog.Error("failed to list allocated IPs", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	virtualIP, err := s.alloc.allocate(allocatedIPs)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "no IPs available")
		return
	}

	nodeID := uuid.New().String()
	authToken := uuid.New().String()
	now := time.Now().UTC()

	nodeName := sql.NullString{}
	if req.NodeName != "" {
		nodeName = sql.NullString{String: req.NodeName, Valid: true}
	}

	node := &db.NodeRecord{
		NodeID:              nodeID,
		NodeName:            nodeName,
		PublicKey:           pubKey,
		PrivateKeyEncrypted: privKey,
		VirtualIP:           virtualIP,
		AuthToken:           authToken,
		Status:              "registered",
		ListenPort:          s.defaultPort,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.db.InsertNode(node); err != nil {
		slog.Error("failed to insert node", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build config TOML
	peers, _ := s.db.ListActiveNodes()
	configTOML := generateConfigTOML(node, peers, s.coordAddr)

	slog.Info("node registered", "node_id", nodeID, "virtual_ip", virtualIP)

	writeJSON(w, http.StatusCreated, registerResponse{
		NodeID:     nodeID,
		PrivateKey: base64.StdEncoding.EncodeToString(privKey),
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
		VirtualIP:  virtualIP,
		ConfigTOML: configTOML,
		AuthToken:  authToken,
	})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	tok := s.extractToken(r)
	if tok == "" {
		writeError(w, http.StatusUnauthorized, "missing Authorization")
		return
	}
	nodeID, ok, err := s.db.ValidatePeerToken(tok)
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	var body struct {
		NewToken string `json:"new_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.NewToken) < 16 {
		writeError(w, http.StatusBadRequest, "new_token too short or missing")
		return
	}
	if err := s.db.RotateNodeToken(nodeID, body.NewToken); err != nil {
		slog.Error("token rotation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slog.Info("peer token rotated", "node_id", nodeID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePublishUpdate(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.resolveCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	desc := strings.TrimSpace(r.Header.Get("X-Update-Description"))
	if desc == "" {
		writeError(w, http.StatusBadRequest, "X-Update-Description header required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 500<<20))
	if err != nil || len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty body")
		return
	}
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	id, err := s.db.InsertUpdate(desc, hashHex, int64(len(body)), caller)
	if err != nil {
		slog.Error("insert update failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := os.WriteFile(s.updatePath(id), body, 0o644); err != nil {
		slog.Error("write update binary failed", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to store binary")
		return
	}
	slog.Info("update published", "id", id, "caller", caller, "bytes", len(body))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id,
		"binary_hash": hashHex,
		"binary_size": len(body),
		"uploaded_by": caller,
		"description": desc,
	})
}

func (s *Server) handleGetLatestUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.resolveCaller(r); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rec, err := s.db.GetLatestUpdate()
	if err != nil || rec == nil {
		writeError(w, http.StatusNotFound, "no updates available")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleDownloadLatestBinary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.resolveCaller(r); !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rec, err := s.db.GetLatestUpdate()
	if err != nil || rec == nil {
		writeError(w, http.StatusNotFound, "no updates available")
		return
	}
	data, err := os.ReadFile(s.updatePath(rec.ID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "binary not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Update-Id", fmt.Sprintf("%d", rec.ID))
	w.Header().Set("X-Binary-Hash", rec.BinaryHash)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleListUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	recs, err := s.db.ListUpdates()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) updatePath(id int64) string {
	return filepath.Join(s.updatesDir, fmt.Sprintf("%d.bin", id))
}

// --- Config TOML generation (mirrors Rust config_generator) ---

func generateConfigTOML(node *db.NodeRecord, peers []*db.NodeRecord, coordServer string) string {
	privKeyB64 := base64.StdEncoding.EncodeToString(node.PrivateKeyEncrypted)
	var sb strings.Builder
	fmt.Fprintf(&sb, "[node]\nprivate_key = %q\nlisten_port = %d\nvirtual_ip = %q\ntun_name = \"meshlink0\"\n\n[coordination]\nserver = %q\n",
		privKeyB64, node.ListenPort, node.VirtualIP, coordServer)
	for _, p := range peers {
		if p.NodeID == node.NodeID {
			continue
		}
		pubKeyB64 := base64.StdEncoding.EncodeToString(p.PublicKey)
		host := stripCIDR(p.VirtualIP)
		fmt.Fprintf(&sb, "\n[[peers]]\npublic_key = %q\nallowed_ips = [%q]\n", pubKeyB64, host+"/32")
		if p.Endpoint.Valid && p.Endpoint.String != "" {
			fmt.Fprintf(&sb, "endpoint = %q\n", p.Endpoint.String)
		}
		if p.IPv6Endpoint.Valid && p.IPv6Endpoint.String != "" {
			fmt.Fprintf(&sb, "ipv6_endpoint = %q\n", p.IPv6Endpoint.String)
		}
	}
	return sb.String()
}

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

// generateKeypair generates an X25519 keypair and returns (private, public).
func generateKeypair() ([]byte, []byte, error) {
	// Use x25519 from golang.org/x/crypto (already a dependency via go-paseto)
	privKey := make([]byte, 32)
	if _, err := io.ReadFull(randReader(), privKey); err != nil {
		return nil, nil, err
	}
	// Clamp per X25519 spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := x25519ScalarMult(privKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func randReader() io.Reader {
	return cryptoRandReader{}
}

type cryptoRandReader struct{}

func (cryptoRandReader) Read(b []byte) (int, error) {
	return cryptoRand(b)
}

// bindAddr combines bind address and port for net.Listen.
func bindAddr(bindAddr string, port int) string {
	return net.JoinHostPort(bindAddr, fmt.Sprintf("%d", port))
}
