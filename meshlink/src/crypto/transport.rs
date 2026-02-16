/// Wire format for a data packet: [type: 1 byte = 0x04][plaintext payload]
pub const DATA_PACKET_TYPE: u8 = 0x04;

/// Wrap a plaintext packet for the wire: prepend the type byte.
pub fn wrap_packet(plaintext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + plaintext.len());
    packet.push(DATA_PACKET_TYPE);
    packet.extend_from_slice(plaintext);
    packet
}

/// Unwrap a wire data packet: strip the type byte, return the payload.
pub fn unwrap_packet(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() >= 2 && packet[0] == DATA_PACKET_TYPE {
        Some(&packet[1..])
    } else {
        None
    }
}

/// Check if a received packet is a data packet.
pub fn is_data_packet(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == DATA_PACKET_TYPE
}
