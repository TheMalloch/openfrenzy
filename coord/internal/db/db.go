package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

// NodeRecord mirrors the nodes table row.
type NodeRecord struct {
	NodeID              string
	NodeName            sql.NullString
	PublicKey           []byte
	PrivateKeyEncrypted []byte
	VirtualIP           string
	AuthToken           string
	Status              string
	Endpoint            sql.NullString
	IPv6Endpoint        sql.NullString
	LanEndpoint         sql.NullString
	ListenPort          int
	LastHeartbeat       sql.NullTime
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// UpdateRecord mirrors the updates table row.
type UpdateRecord struct {
	ID          int64
	Description string
	BinaryHash  string
	BinarySize  int64
	UploadedBy  string
	UploadedAt  time.Time
}

// DB wraps a SQLite connection pool.
type DB struct {
	sql *sql.DB
}

// Open opens (or creates) the SQLite database at path and runs schema migrations.
func Open(path string) (*DB, error) {
	dsn := path
	if len(path) > 0 && path[:7] != "file://" && path[:8] != "sqlite://" {
		dsn = "file:" + path + "?_foreign_keys=on&_journal_mode=WAL"
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	sqlDB.SetMaxOpenConns(1) // SQLite WAL is safe with one writer
	db := &DB{sql: sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	slog.Info("database ready", "path", path)
	return db, nil
}

func (d *DB) Close() error { return d.sql.Close() }

func (d *DB) migrate() error {
	_, err := d.sql.Exec(`
		CREATE TABLE IF NOT EXISTS nodes (
			node_id TEXT PRIMARY KEY,
			node_name TEXT,
			public_key BLOB NOT NULL UNIQUE,
			private_key_encrypted BLOB NOT NULL,
			virtual_ip TEXT NOT NULL UNIQUE,
			auth_token TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'registered'
				CHECK(status IN ('registered','active','stale','deregistered')),
			endpoint TEXT,
			ipv6_endpoint TEXT,
			lan_endpoint TEXT,
			listen_port INTEGER NOT NULL DEFAULT 51820,
			last_heartbeat TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		);
		CREATE TABLE IF NOT EXISTS updates (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			description TEXT NOT NULL,
			binary_hash TEXT NOT NULL,
			binary_size INTEGER NOT NULL,
			uploaded_by TEXT NOT NULL,
			uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
		);
	`)
	return err
}

// DropAllTables removes all tables.
func (d *DB) DropAllTables() error {
	_, err := d.sql.Exec(`DROP TABLE IF EXISTS updates; DROP TABLE IF EXISTS nodes;`)
	return err
}

// --- Node operations ---

func (d *DB) InsertNode(n *NodeRecord) error {
	_, err := d.sql.Exec(
		`INSERT INTO nodes (node_id, node_name, public_key, private_key_encrypted,
			virtual_ip, auth_token, status, endpoint, ipv6_endpoint, listen_port,
			last_heartbeat, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		n.NodeID, n.NodeName, n.PublicKey, n.PrivateKeyEncrypted,
		n.VirtualIP, n.AuthToken, n.Status, n.Endpoint, n.IPv6Endpoint,
		n.ListenPort, n.LastHeartbeat,
		n.CreatedAt.UTC().Format(time.RFC3339),
		n.UpdatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (d *DB) GetNode(nodeID string) (*NodeRecord, error) {
	return d.scanNode(d.sql.QueryRow(`SELECT * FROM nodes WHERE node_id = ?`, nodeID))
}

func (d *DB) GetNodeByPubkey(pubkey []byte) (*NodeRecord, error) {
	return d.scanNode(d.sql.QueryRow(`SELECT * FROM nodes WHERE public_key = ?`, pubkey))
}

func (d *DB) AllocatedIPs() ([]string, error) {
	rows, err := d.sql.Query(`SELECT virtual_ip FROM nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (d *DB) ListActiveNodes() ([]*NodeRecord, error) {
	rows, err := d.sql.Query(
		`SELECT * FROM nodes WHERE status IN ('registered','active') ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (d *DB) ListAllNodes() ([]*NodeRecord, error) {
	rows, err := d.sql.Query(`SELECT * FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func (d *DB) SetNodeStatus(nodeID, status string) error {
	_, err := d.sql.Exec(
		`UPDATE nodes SET status=?, updated_at=datetime('now') WHERE node_id=?`,
		status, nodeID,
	)
	return err
}

func (d *DB) UpdateEndpointByPubkey(pubkey []byte, endpoint string) (bool, error) {
	res, err := d.sql.Exec(
		`UPDATE nodes SET endpoint=?, last_heartbeat=datetime('now'),
			updated_at=datetime('now'), status='active'
			WHERE public_key=? AND status IN ('registered','active')`,
		endpoint, pubkey,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) UpdateIPv6EndpointByPubkey(pubkey []byte, ep string) (bool, error) {
	res, err := d.sql.Exec(
		`UPDATE nodes SET ipv6_endpoint=?, updated_at=datetime('now')
			WHERE public_key=? AND status IN ('registered','active')`,
		ep, pubkey,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) UpdateLanEndpointByPubkey(pubkey []byte, lanEndpoint *string) (bool, error) {
	res, err := d.sql.Exec(
		`UPDATE nodes SET lan_endpoint=?, updated_at=datetime('now')
			WHERE public_key=? AND status IN ('registered','active')`,
		lanEndpoint, pubkey,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (d *DB) MarkStaleNodes(staleSeconds int64) (int64, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(staleSeconds) * time.Second).Format(time.RFC3339)
	res, err := d.sql.Exec(
		`UPDATE nodes SET status='stale', updated_at=datetime('now')
			WHERE status='active' AND last_heartbeat < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) ValidatePeerToken(token string) (string, bool, error) {
	var nodeID string
	err := d.sql.QueryRow(
		`SELECT node_id FROM nodes WHERE auth_token=? AND status IN ('registered','active')`,
		token,
	).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return nodeID, true, nil
}

func (d *DB) RotateNodeToken(nodeID, newToken string) error {
	_, err := d.sql.Exec(
		`UPDATE nodes SET auth_token=?, updated_at=datetime('now') WHERE node_id=?`,
		newToken, nodeID,
	)
	return err
}

// --- Update operations ---

func (d *DB) InsertUpdate(description, hash string, size int64, uploadedBy string) (int64, error) {
	res, err := d.sql.Exec(
		`INSERT INTO updates (description, binary_hash, binary_size, uploaded_by) VALUES (?,?,?,?)`,
		description, hash, size, uploadedBy,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) GetLatestUpdate() (*UpdateRecord, error) {
	row := d.sql.QueryRow(`SELECT id, description, binary_hash, binary_size, uploaded_by, uploaded_at FROM updates ORDER BY uploaded_at DESC LIMIT 1`)
	return scanUpdate(row)
}

func (d *DB) ListUpdates() ([]*UpdateRecord, error) {
	rows, err := d.sql.Query(`SELECT id, description, binary_hash, binary_size, uploaded_by, uploaded_at FROM updates ORDER BY uploaded_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recs []*UpdateRecord
	for rows.Next() {
		r, err := scanUpdate(rows)
		if err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

// --- Scanning helpers ---

type scanner interface {
	Scan(dest ...any) error
}

func scanUpdate(s scanner) (*UpdateRecord, error) {
	var r UpdateRecord
	var uploadedAt string
	err := s.Scan(&r.ID, &r.Description, &r.BinaryHash, &r.BinarySize, &r.UploadedBy, &uploadedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.UploadedAt, _ = parseTime(uploadedAt)
	return &r, nil
}

func (d *DB) scanNode(row *sql.Row) (*NodeRecord, error) {
	var n NodeRecord
	var createdAt, updatedAt string
	var lastHeartbeat sql.NullString
	err := row.Scan(
		&n.NodeID, &n.NodeName, &n.PublicKey, &n.PrivateKeyEncrypted,
		&n.VirtualIP, &n.AuthToken, &n.Status,
		&n.Endpoint, &n.IPv6Endpoint, &n.LanEndpoint,
		&n.ListenPort, &lastHeartbeat, &createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.CreatedAt, _ = parseTime(createdAt)
	n.UpdatedAt, _ = parseTime(updatedAt)
	if lastHeartbeat.Valid {
		t, _ := parseTime(lastHeartbeat.String)
		n.LastHeartbeat = sql.NullTime{Time: t, Valid: true}
	}
	return &n, nil
}

func scanNodes(rows *sql.Rows) ([]*NodeRecord, error) {
	var nodes []*NodeRecord
	for rows.Next() {
		var n NodeRecord
		var createdAt, updatedAt string
		var lastHeartbeat sql.NullString
		if err := rows.Scan(
			&n.NodeID, &n.NodeName, &n.PublicKey, &n.PrivateKeyEncrypted,
			&n.VirtualIP, &n.AuthToken, &n.Status,
			&n.Endpoint, &n.IPv6Endpoint, &n.LanEndpoint,
			&n.ListenPort, &lastHeartbeat, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		n.CreatedAt, _ = parseTime(createdAt)
		n.UpdatedAt, _ = parseTime(updatedAt)
		if lastHeartbeat.Valid {
			t, _ := parseTime(lastHeartbeat.String)
			n.LastHeartbeat = sql.NullTime{Time: t, Valid: true}
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

func parseTime(s string) (time.Time, error) {
	// SQLite stores either RFC3339 or "YYYY-MM-DD HH:MM:SS"
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time: %q", s)
}
