package cli

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"meshlink/coord/internal/db"
)

// Listener handles admin commands over a Unix socket.
type Listener struct {
	db       *db.DB
	sockPath string
}

func NewListener(database *db.DB, sockPath string) *Listener {
	return &Listener{db: database, sockPath: sockPath}
}

func (l *Listener) Run() {
	os.Remove(l.sockPath)
	ln, err := net.Listen("unix", l.sockPath)
	if err != nil {
		slog.Warn("CLI socket unavailable", "path", l.sockPath, "err", err)
		return
	}
	if err := os.Chmod(l.sockPath, 0o660); err != nil {
		slog.Warn("could not chmod CLI socket", "err", err)
	}
	slog.Info("CLI listener started", "path", l.sockPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("CLI accept error", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *Listener) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		resp := l.process(line)
		fmt.Fprintln(conn, resp)
	}
}

func (l *Listener) process(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "error: empty command"
	}
	switch parts[0] {
	case "ping":
		return "pong"

	case "list-peers":
		nodes, err := l.db.ListAllNodes()
		if err != nil {
			return "error: " + err.Error()
		}
		if len(nodes) == 0 {
			return "No peers registered."
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%-38s %-16s %-16s %-15s %-20s\n", "NODE ID", "NAME", "VIRTUAL IP", "STATUS", "LAST SEEN")
		sb.WriteString(strings.Repeat("-", 108) + "\n")
		for _, n := range nodes {
			name := "-"
			if n.NodeName.Valid {
				name = n.NodeName.String
			}
			vip := stripCIDR(n.VirtualIP)
			lastSeen := "-"
			if n.LastHeartbeat.Valid {
				lastSeen = n.LastHeartbeat.Time.Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(&sb, "%-38s %-16s %-16s %-15s %-20s\n",
				n.NodeID, name, vip, n.Status, lastSeen)
		}
		return strings.TrimRight(sb.String(), "\n")

	case "show-peer":
		if len(parts) < 2 {
			return "usage: show-peer <id>"
		}
		n, err := l.db.GetNode(parts[1])
		if err != nil {
			return "error: " + err.Error()
		}
		if n == nil {
			return "Peer not found: " + parts[1]
		}
		var sb strings.Builder
		name := "-"
		if n.NodeName.Valid {
			name = n.NodeName.String
		}
		ep := "-"
		if n.Endpoint.Valid {
			ep = n.Endpoint.String
		}
		ep6 := "-"
		if n.IPv6Endpoint.Valid {
			ep6 = n.IPv6Endpoint.String
		}
		lan := "-"
		if n.LanEndpoint.Valid {
			lan = n.LanEndpoint.String
		}
		hb := "-"
		if n.LastHeartbeat.Valid {
			hb = n.LastHeartbeat.Time.Format(time.RFC3339)
		}
		fmt.Fprintf(&sb,
			"Node ID:        %s\nName:           %s\nVirtual IP:     %s\nStatus:         %s\n"+
				"Endpoint:       %s\nIPv6 endpoint:  %s\nLAN endpoint:   %s\n"+
				"Listen port:    %d\nLast heartbeat: %s\nCreated at:     %s\nUpdated at:     %s",
			n.NodeID, name, stripCIDR(n.VirtualIP), n.Status,
			ep, ep6, lan, n.ListenPort, hb,
			n.CreatedAt.Format(time.RFC3339), n.UpdatedAt.Format(time.RFC3339),
		)
		return sb.String()

	case "disable-peer":
		if len(parts) < 2 {
			return "usage: disable-peer <id>"
		}
		if err := l.db.SetNodeStatus(parts[1], "deregistered"); err != nil {
			return "error: " + err.Error()
		}
		return "Peer " + parts[1] + " disabled."

	case "enable-peer":
		if len(parts) < 2 {
			return "usage: enable-peer <id>"
		}
		if err := l.db.SetNodeStatus(parts[1], "registered"); err != nil {
			return "error: " + err.Error()
		}
		return "Peer " + parts[1] + " enabled."

	default:
		return "unknown command: " + parts[0]
	}
}

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}
