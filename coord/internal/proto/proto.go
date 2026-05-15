package proto

// UDP wire protocol constants (must match meshlink Rust client).
const (
	NATDetect    byte = 0x10
	NATDetectResp byte = 0x11
	Register     byte = 0x30
	PeerListReq  byte = 0x31
	PeerListResp byte = 0x32
	Keepalive    byte = 0x33
)
