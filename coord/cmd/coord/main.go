package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/BurntSushi/toml"
	"meshlink/coord/internal/cli"
	"meshlink/coord/internal/db"
	httpsvr "meshlink/coord/internal/http"
	"meshlink/coord/internal/udp"
)

// --- Config structs ---

type configFile struct {
	Database databaseConfig `toml:"database"`
	Network  networkConfig  `toml:"network"`
	Server   serverConfig   `toml:"server"`
	Admin    adminConfig    `toml:"admin"`
	Peers    peersConfig    `toml:"peers"`
	Logging  loggingConfig  `toml:"logging"`
	Updates  updatesConfig  `toml:"updates"`
	Invites  invitesConfig  `toml:"invites"`
}

type databaseConfig struct {
	Path string `toml:"path"`
}

type networkConfig struct {
	MeshCIDR string `toml:"mesh_cidr"`
}

type serverConfig struct {
	HTTPPort        int    `toml:"http_port"`
	UDPPort         int    `toml:"udp_port"`
	BindAddress     string `toml:"bind_address"`
	ExternalAddress string `toml:"external_address"`
	CoordAddr       string `toml:"coord_addr"`
}

type adminConfig struct {
	Token string `toml:"token"`
}

type peersConfig struct {
	StaleTimeoutSecs    int64 `toml:"stale_timeout_secs"`
	CleanupIntervalSecs int64 `toml:"cleanup_interval_secs"`
	DefaultListenPort   int   `toml:"default_listen_port"`
}

type loggingConfig struct {
	Level string `toml:"level"`
}

type updatesConfig struct {
	Dir string `toml:"dir"`
}

type invitesConfig struct {
	PasetoKeyHex string `toml:"paseto_key"`
}

type coordConfig struct {
	DatabasePath        string
	MeshCIDR            string
	HTTPPort            int
	UDPPort             int
	BindAddress         string
	ExternalAddress     string
	CoordAddr           string
	AdminToken          string
	StaleTimeoutSecs    int64
	CleanupIntervalSecs int64
	DefaultListenPort   int
	LogLevel            string
	UpdatesDir          string
	PasetoKey           paseto.V4SymmetricKey
	CLISockPath         string
}

func defaults() coordConfig {
	return coordConfig{
		DatabasePath:        "/var/lib/meshlink/coord.db",
		MeshCIDR:            "10.0.0.0/24",
		HTTPPort:            4001,
		UDPPort:             4000,
		BindAddress:         "[::]",
		StaleTimeoutSecs:    120,
		CleanupIntervalSecs: 60,
		DefaultListenPort:   51820,
		LogLevel:            "info",
		UpdatesDir:          "/var/lib/meshlink/updates",
		CLISockPath:         "/run/meshlink/coord.sock",
	}
}

func loadConfig(path string) (coordConfig, error) {
	cfg := defaults()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	var f configFile
	if _, err := toml.DecodeFile(path, &f); err != nil {
		return cfg, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if f.Database.Path != "" {
		cfg.DatabasePath = f.Database.Path
	}
	if f.Network.MeshCIDR != "" {
		cfg.MeshCIDR = f.Network.MeshCIDR
	}
	if f.Server.HTTPPort != 0 {
		cfg.HTTPPort = f.Server.HTTPPort
	}
	if f.Server.UDPPort != 0 {
		cfg.UDPPort = f.Server.UDPPort
	}
	if f.Server.BindAddress != "" {
		cfg.BindAddress = f.Server.BindAddress
	}
	if f.Server.ExternalAddress != "" {
		cfg.ExternalAddress = f.Server.ExternalAddress
	}
	if f.Server.CoordAddr != "" {
		cfg.CoordAddr = f.Server.CoordAddr
	}
	if f.Admin.Token != "" {
		cfg.AdminToken = f.Admin.Token
	}
	if f.Peers.StaleTimeoutSecs != 0 {
		cfg.StaleTimeoutSecs = f.Peers.StaleTimeoutSecs
	}
	if f.Peers.CleanupIntervalSecs != 0 {
		cfg.CleanupIntervalSecs = f.Peers.CleanupIntervalSecs
	}
	if f.Peers.DefaultListenPort != 0 {
		cfg.DefaultListenPort = f.Peers.DefaultListenPort
	}
	if f.Logging.Level != "" {
		cfg.LogLevel = f.Logging.Level
	}
	if f.Updates.Dir != "" {
		cfg.UpdatesDir = f.Updates.Dir
	}
	if f.Invites.PasetoKeyHex != "" {
		keyBytes, err := hex.DecodeString(f.Invites.PasetoKeyHex)
		if err != nil || len(keyBytes) != 32 {
			return cfg, fmt.Errorf("invites.paseto_key must be 64 hex chars (32 bytes)")
		}
		var arr [32]byte
		copy(arr[:], keyBytes)
		cfg.PasetoKey, err = paseto.V4SymmetricKeyFromBytes(arr[:])
		if err != nil {
			return cfg, fmt.Errorf("invalid paseto key: %w", err)
		}
	}

	return cfg, nil
}

func main() {
	configPath := flag.String("config", "/etc/meshlink/coord.toml", "path to coord config file")
	dbPath := flag.String("database-path", "", "SQLite database file path")
	meshCIDR := flag.String("mesh-cidr", "", "mesh network CIDR")
	httpPort := flag.Int("http-port", 0, "HTTP API port")
	udpPort := flag.Int("udp-port", 0, "UDP coordination port")
	bindAddr := flag.String("bind-address", "", "bind address")
	extAddr := flag.String("external-address", "", "external address for peers")
	adminToken := flag.String("admin-token", "", "admin API bearer token")
	logLevel := flag.String("log-level", "", "log level (debug, info, warn, error)")
	updatesDir := flag.String("updates-dir", "", "update binaries directory")
	cliSock := flag.String("cli-sock", "", "Unix socket path for admin CLI")
	genKey := flag.Bool("gen-paseto-key", false, "generate a PASETO key and exit")
	createInvite := flag.Bool("create-invite", false, "create an invite token and exit")
	inviteExpiry := flag.Duration("invite-expiry", 24*time.Hour, "invite expiry duration (with --create-invite)")
	flag.Parse()

	if *genKey {
		key := paseto.NewV4SymmetricKey()
		fmt.Printf("paseto_key = %q\n", hex.EncodeToString(key.ExportBytes()))
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// CLI flag overrides
	if *dbPath != "" {
		cfg.DatabasePath = *dbPath
	}
	if *meshCIDR != "" {
		cfg.MeshCIDR = *meshCIDR
	}
	if *httpPort != 0 {
		cfg.HTTPPort = *httpPort
	}
	if *udpPort != 0 {
		cfg.UDPPort = *udpPort
	}
	if *bindAddr != "" {
		cfg.BindAddress = *bindAddr
	}
	if *extAddr != "" {
		cfg.ExternalAddress = *extAddr
	}
	if *adminToken != "" {
		cfg.AdminToken = *adminToken
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	if *updatesDir != "" {
		cfg.UpdatesDir = *updatesDir
	}
	if *cliSock != "" {
		cfg.CLISockPath = *cliSock
	}

	// Derive coordAddr if not set
	if cfg.CoordAddr == "" {
		host := cfg.ExternalAddress
		if host == "" {
			host = "0.0.0.0"
		}
		cfg.CoordAddr = fmt.Sprintf("%s:%d", host, cfg.UDPPort)
	}

	// Set up logger
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Ensure a PASETO key exists (generate ephemeral if not configured)
	zeroKey := paseto.V4SymmetricKey{}
	if cfg.PasetoKey == zeroKey {
		cfg.PasetoKey = paseto.NewV4SymmetricKey()
		slog.Warn("no paseto_key configured — generated ephemeral key; invite tokens will be invalid after restart")
	}

	// --create-invite subcommand
	if *createInvite {
		expiresAt := time.Now().Add(*inviteExpiry)
		tok := paseto.NewToken()
		tok.SetExpiration(expiresAt)
		tok.SetIssuedAt(time.Now())
		tok.SetNotBefore(time.Now())
		encrypted := tok.V4Encrypt(cfg.PasetoKey, nil)
		fmt.Printf("Invite token: %s\nExpires at:   %s\n", encrypted, expiresAt.Format(time.RFC3339))
		return
	}

	// Open database
	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		slog.Error("database open failed", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	// Bind UDP socket
	udpAddr := net.JoinHostPort(cfg.BindAddress, fmt.Sprintf("%d", cfg.UDPPort))
	// Strip brackets from bind address for UDP
	host := cfg.BindAddress
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	udpAddrParsed, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.UDPPort)))
	if err != nil {
		slog.Error("resolve UDP address", "addr", udpAddr, "err", err)
		os.Exit(1)
	}
	udpConn, err := net.ListenUDP("udp", udpAddrParsed)
	if err != nil {
		slog.Error("bind UDP", "addr", udpAddrParsed, "err", err)
		os.Exit(1)
	}
	slog.Info("UDP socket bound", "addr", udpAddrParsed)

	peerMap := udp.NewPeerMap()
	udpServer := udp.NewServer(udpConn, database, peerMap, cfg.StaleTimeoutSecs, cfg.CleanupIntervalSecs)

	// Build HTTP server
	httpSvr, err := httpsvr.NewServer(httpsvr.Config{
		DB:          database,
		MeshCIDR:    cfg.MeshCIDR,
		CoordAddr:   cfg.CoordAddr,
		AdminToken:  cfg.AdminToken,
		DefaultPort: cfg.DefaultListenPort,
		UpdatesDir:  cfg.UpdatesDir,
		PasetoKey:   cfg.PasetoKey,
		UDPServer:   udpServer,
		PeerMap:     peerMap,
	})
	if err != nil {
		slog.Error("http server init failed", "err", err)
		os.Exit(1)
	}

	// CLI listener
	cliListener := cli.NewListener(database, cfg.CLISockPath)
	go cliListener.Run()

	// Start servers
	go udpServer.Run()
	go udpServer.StaleChecker()

	httpAddr := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.HTTPPort))
	slog.Info("coordination server running",
		"udp_port", cfg.UDPPort,
		"http_port", cfg.HTTPPort,
		"coord_addr", cfg.CoordAddr,
	)
	if err := httpSvr.ListenAndServe(httpAddr); err != nil {
		slog.Error("HTTP server failed", "err", err)
		os.Exit(1)
	}
}
