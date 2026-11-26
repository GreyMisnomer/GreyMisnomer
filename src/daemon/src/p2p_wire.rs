// src/daemon/src/p2p_wire.rs
// RFC-008 §3: P2P Wire Framing, Message Types & BLAKE3 Checksums

use thiserror::Error;

pub const P2P_MAGIC: [u8; 4] = [0x47, 0x4D, 0x32, 0x50]; // "GM2P"
/// 4B magic + 1B msg_type + 1B flags + 2B reserved + 8B timestamp + 4B payload_len
pub const HEADER_LEN: usize = 20;
pub const CHECKSUM_LEN: usize = 32;
pub const MAX_PAYLOAD_SIZE: usize = 1_048_576; // 1 MiB frame cap

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    TxIntent = 0x01,
    CheckpointAnnouncement = 0x02,
    TileRequest = 0x03,
    TileResponse = 0x04,
    BlobRequest = 0x05,
    BlobChunkResponse = 0x06,
    PeerPing = 0x07,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Result<Self, P2pWireError> {
        match val {
            0x01 => Ok(Self::TxIntent),
            0x02 => Ok(Self::CheckpointAnnouncement),
            0x03 => Ok(Self::TileRequest),
            0x04 => Ok(Self::TileResponse),
            0x05 => Ok(Self::BlobRequest),
            0x06 => Ok(Self::BlobChunkResponse),
            0x07 => Ok(Self::PeerPing),
            other => Err(P2pWireError::UnknownMessageType(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub msg_type: MessageType,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum P2pWireError {
    #[error("Frame truncated: expected at least {0} bytes")]
    Truncated(usize),
    #[error("Invalid P2P magic header: expected 'GM2P', got {0:02x?}")]
    InvalidMagic([u8; 4]),
    #[error("Unknown P2P message type: 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("Payload length {len} exceeds max limit of {max} bytes")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("Frame checksum mismatch: payload tampered or corrupted")]
    ChecksumMismatch,
}

impl WireFrame {
    pub fn new(msg_type: MessageType, timestamp: u64, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            timestamp,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, P2pWireError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(P2pWireError::PayloadTooLarge {
                len: self.payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut buf = Vec::with_capacity(HEADER_LEN + self.payload.len() + CHECKSUM_LEN);
        buf.extend_from_slice(&P2P_MAGIC);
        buf.push(self.msg_type as u8);
        buf.push(0x00); // flags
        buf.extend_from_slice(&[0x00, 0x00]); // reserved
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        // Compute BLAKE3 checksum over header bytes (after magic) and payload
        let checksum = blake3::hash(&buf[4..]);
        buf.extend_from_slice(checksum.as_bytes());

        Ok(buf)
    }

    /// Decodes a complete `WireFrame` from a streaming TCP read buffer.
    /// Returns `Ok(None)` when more bytes are needed from the socket, or
    /// `Ok(Some((frame, bytes_consumed)))` on success.
    pub fn decode_from_buffer(bytes: &[u8]) -> Result<Option<(Self, usize)>, P2pWireError> {
        if bytes.len() < HEADER_LEN {
            return Ok(None);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != P2P_MAGIC {
            return Err(P2pWireError::InvalidMagic(magic));
        }

        let msg_type = MessageType::from_u8(bytes[4])?;
        // bytes[5] flags, bytes[6..8] reserved
        let timestamp = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| P2pWireError::Truncated(16))?,
        );
        let payload_len = u32::from_be_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| P2pWireError::Truncated(20))?,
        ) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(P2pWireError::PayloadTooLarge {
                len: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let expected_total_len = HEADER_LEN + payload_len + CHECKSUM_LEN;
        if bytes.len() < expected_total_len {
            return Ok(None);
        }

        let payload = bytes[HEADER_LEN..HEADER_LEN + payload_len].to_vec();
        let expected_checksum = blake3::hash(&bytes[4..HEADER_LEN + payload_len]);
        let provided_checksum = &bytes[HEADER_LEN + payload_len..expected_total_len];

        if expected_checksum.as_bytes() != provided_checksum {
            return Err(P2pWireError::ChecksumMismatch);
        }

        Ok(Some((
            Self {
                msg_type,
                timestamp,
                payload,
            },
            expected_total_len,
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, P2pWireError> {
        match Self::decode_from_buffer(bytes)? {
            Some((frame, _)) => Ok(frame),
            None => Err(P2pWireError::Truncated(HEADER_LEN + CHECKSUM_LEN)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_frame_encode_decode_roundtrip() {
        assert_eq!(HEADER_LEN, 20);
        let frame = WireFrame::new(
            MessageType::TxIntent,
            1732450000,
            b"test transaction payload bytes".to_vec(),
        );

        let encoded = frame.encode().expect("encode should succeed");
        assert_eq!(&encoded[0..4], b"GM2P");

        let decoded = WireFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_wire_frame_stream_fragmentation_and_coalescing() {
        let f1 = WireFrame::new(MessageType::PeerPing, 1, b"alice".to_vec());
        let f2 = WireFrame::new(MessageType::TxIntent, 2, b"tx-payload-data".to_vec());

        let mut stream = f1.encode().unwrap();
        let f2_bytes = f2.encode().unwrap();
        stream.extend_from_slice(&f2_bytes);

        // Fragmented byte-by-byte trickle yields None until first frame completes
        for partial_end in 1..f1.encode().unwrap().len() {
            assert_eq!(
                WireFrame::decode_from_buffer(&stream[..partial_end]).unwrap(),
                None
            );
        }

        // Decoding coalesced stream extracts frame 1 then frame 2 cleanly
        let (dec1, len1) = WireFrame::decode_from_buffer(&stream).unwrap().unwrap();
        assert_eq!(dec1, f1);
        let (dec2, len2) = WireFrame::decode_from_buffer(&stream[len1..])
            .unwrap()
            .unwrap();
        assert_eq!(dec2, f2);
        assert_eq!(len1 + len2, stream.len());
    }

    #[test]
    fn test_wire_frame_rejects_bad_magic() {
        let frame = WireFrame::new(MessageType::PeerPing, 100, vec![1, 2, 3]);
        let mut encoded = frame.encode().unwrap();
        encoded[0] = b'X';

        let err = WireFrame::decode(&encoded).unwrap_err();
        assert!(matches!(err, P2pWireError::InvalidMagic(_)));
    }

    #[test]
    fn test_wire_frame_rejects_tampered_payload_checksum() {
        let frame = WireFrame::new(MessageType::CheckpointAnnouncement, 200, vec![42; 64]);
        let mut encoded = frame.encode().unwrap();
        // Tamper with payload byte
        encoded[25] ^= 0xff;

        let err = WireFrame::decode(&encoded).unwrap_err();
        assert_eq!(err, P2pWireError::ChecksumMismatch);
    }

    #[test]
    fn test_wire_frame_rejects_oversized_payload() {
        let huge_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = WireFrame::new(MessageType::BlobChunkResponse, 300, huge_payload);
        let err = frame.encode().unwrap_err();
        assert!(matches!(err, P2pWireError::PayloadTooLarge { .. }));
    }
}
