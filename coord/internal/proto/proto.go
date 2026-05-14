package proto

// UDP wire protocol constants (must match meshlink Rust client).
const (
	Register    byte = 0x30
	PeerListReq byte = 0x31
	PeerListResp byte = 0x32
	Keepalive   byte = 0x33
)
