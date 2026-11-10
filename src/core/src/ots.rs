use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonical 31-byte OpenTimestamps binary proof header magic.
pub const OTS_HEADER_MAGIC: [u8; 31] =
    *b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

const OP_ATTESTATION: u8 = 0x00;
const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_SHA256: u8 = 0x08;
const OP_KECCAK256: u8 = 0x67;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;
const OP_FORK: u8 = 0xff;

/// 8-byte OpenTimestamps Bitcoin block header attestation tag.
pub const BITCOIN_ATTESTATION_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// 8-byte OpenTimestamps pending calendar attestation tag.
pub const PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

const MAX_VARBYTES_LEN: usize = 1 << 20; // 1 MiB safety bound per proof operand
const MAX_FORK_DEPTH: usize = 256;
const MAX_PROOF_STEPS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtsProofReport {
    pub attested_sha256: String,
    pub actual_sha256: String,
    pub digest_matches: bool,
    pub bitcoin_blocks: Vec<u64>,
    pub pending_calendars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OtsError {
    #[error("Invalid OpenTimestamps header magic")]
    InvalidMagic,
    #[error("Unsupported OpenTimestamps proof version {0} (expected 1)")]
    UnsupportedVersion(u64),
    #[error("Unsupported file digest opcode 0x{0:02x} (expected 0x08 SHA-256)")]
    UnsupportedHashOp(u8),
    #[error("Malformed or truncated OpenTimestamps proof: {0}")]
    MalformedProof(String),
    #[error("SHA-256 digest mismatch: proof attests {attested}, target file is {actual}")]
    DigestMismatch { attested: String, actual: String },
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, OtsError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| OtsError::MalformedProof("unexpected EOF".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], OtsError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| OtsError::MalformedProof("offset overflow".into()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| OtsError::MalformedProof("unexpected EOF in slice".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_varuint(&mut self) -> Result<u64, OtsError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let b = self.read_u8()?;
            let low = u64::from(b & 0x7f);
            if shift >= 64 || (shift == 63 && low > 1) {
                return Err(OtsError::MalformedProof("varuint overflows u64".into()));
            }
            value |= low << shift;
            if (b & 0x80) == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn read_varbytes(&mut self, max_len: usize) -> Result<&'a [u8], OtsError> {
        let len_u64 = self.read_varuint()?;
        let len = usize::try_from(len_u64)
            .map_err(|_| OtsError::MalformedProof("varbytes length overflows usize".into()))?;
        if len > max_len {
            return Err(OtsError::MalformedProof(format!(
                "varbytes length {len} exceeds bound {max_len}"
            )));
        }
        self.read_slice(len)
    }
}

fn parse_attestation_payload(
    tag: [u8; 8],
    payload: &[u8],
    bitcoin_blocks: &mut Vec<u64>,
    pending_calendars: &mut Vec<String>,
) -> Result<(), OtsError> {
    if tag == BITCOIN_ATTESTATION_TAG {
        let mut p = Cursor::new(payload);
        let height = p.read_varuint()?;
        if p.remaining() != 0 {
            return Err(OtsError::MalformedProof(
                "trailing bytes inside Bitcoin attestation payload".into(),
            ));
        }
        bitcoin_blocks.push(height);
    } else if tag == PENDING_ATTESTATION_TAG {
        let mut p = Cursor::new(payload);
        let url_bytes = p.read_varbytes(4096)?;
        if p.remaining() != 0 {
            return Err(OtsError::MalformedProof(
                "trailing bytes inside pending attestation payload".into(),
            ));
        }
        let url = std::str::from_utf8(url_bytes)
            .map_err(|_| OtsError::MalformedProof("non-UTF-8 pending calendar URI".into()))?;
        pending_calendars.push(url.to_string());
    }
    Ok(())
}

fn parse_timestamp_tree(
    cur: &mut Cursor<'_>,
    depth: usize,
    steps: &mut usize,
    bitcoin_blocks: &mut Vec<u64>,
    pending_calendars: &mut Vec<String>,
) -> Result<(), OtsError> {
    if depth > MAX_FORK_DEPTH {
        return Err(OtsError::MalformedProof(
            "fork depth exceeds safety limit".into(),
        ));
    }

    loop {
        *steps += 1;
        if *steps > MAX_PROOF_STEPS {
            return Err(OtsError::MalformedProof(
                "operation count exceeds safety limit".into(),
            ));
        }

        let tag = cur.read_u8()?;
        match tag {
            OP_FORK => {
                parse_timestamp_tree(cur, depth + 1, steps, bitcoin_blocks, pending_calendars)?;
            }
            OP_ATTESTATION => {
                let tag_bytes = cur.read_slice(8)?;
                let mut aid = [0u8; 8];
                aid.copy_from_slice(tag_bytes);
                let payload = cur.read_varbytes(MAX_VARBYTES_LEN)?;
                parse_attestation_payload(aid, payload, bitcoin_blocks, pending_calendars)?;
                return Ok(());
            }
            OP_APPEND | OP_PREPEND => {
                let _operand = cur.read_varbytes(MAX_VARBYTES_LEN)?;
            }
            OP_REVERSE | OP_HEXLIFY | OP_SHA256 | OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 => {}
            other => {
                return Err(OtsError::MalformedProof(format!(
                    "unsupported OpenTimestamps opcode 0x{other:02x}"
                )));
            }
        }
    }
}

/// Parse an OpenTimestamps `.ots` proof and inspect whether its committed SHA-256
/// digest matches `target_bytes`. Does not fail on digest mismatch; check
/// `report.digest_matches` or call [`verify_ots_bytes`] for strict error behavior.
pub fn parse_ots_proof(ots_bytes: &[u8], target_bytes: &[u8]) -> Result<OtsProofReport, OtsError> {
    if ots_bytes.len() < OTS_HEADER_MAGIC.len() || ots_bytes[..31] != OTS_HEADER_MAGIC {
        return Err(OtsError::InvalidMagic);
    }

    let mut cur = Cursor::new(&ots_bytes[31..]);
    let version = cur.read_varuint()?;
    if version != 1 {
        return Err(OtsError::UnsupportedVersion(version));
    }

    let file_hash_op = cur.read_u8()?;
    if file_hash_op != OP_SHA256 {
        return Err(OtsError::UnsupportedHashOp(file_hash_op));
    }

    let attested_slice = cur.read_slice(32)?;
    let attested_sha256 = hex::encode(attested_slice);

    let actual_digest = Sha256::digest(target_bytes);
    let actual_sha256 = hex::encode(actual_digest);
    let digest_matches = attested_slice == actual_digest.as_slice();

    let mut bitcoin_blocks = Vec::new();
    let mut pending_calendars = Vec::new();
    let mut steps = 0usize;
    parse_timestamp_tree(
        &mut cur,
        0,
        &mut steps,
        &mut bitcoin_blocks,
        &mut pending_calendars,
    )?;

    if cur.remaining() != 0 {
        return Err(OtsError::MalformedProof(format!(
            "{} unexpected trailing bytes after timestamp tree",
            cur.remaining()
        )));
    }

    bitcoin_blocks.sort_unstable();
    bitcoin_blocks.dedup();
    pending_calendars.sort();
    pending_calendars.dedup();

    Ok(OtsProofReport {
        attested_sha256,
        actual_sha256,
        digest_matches,
        bitcoin_blocks,
        pending_calendars,
    })
}

/// Strictly verify that `ots_bytes` is a structurally valid OpenTimestamps proof
/// whose committed SHA-256 file digest equals `Sha256::digest(target_bytes)`.
pub fn verify_ots_bytes(ots_bytes: &[u8], target_bytes: &[u8]) -> Result<OtsProofReport, OtsError> {
    let report = parse_ots_proof(ots_bytes, target_bytes)?;
    if !report.digest_matches {
        return Err(OtsError::DigestMismatch {
            attested: report.attested_sha256,
            actual: report.actual_sha256,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varuint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn build_synthetic_ots(target_bytes: &[u8], btc_height: u64) -> Vec<u8> {
        let digest = Sha256::digest(target_bytes);
        let mut out = Vec::new();
        out.extend_from_slice(&OTS_HEADER_MAGIC);
        encode_varuint(1, &mut out);
        out.push(OP_SHA256);
        out.extend_from_slice(&digest);
        out.push(OP_ATTESTATION);
        out.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
        let mut height_payload = Vec::new();
        encode_varuint(btc_height, &mut height_payload);
        encode_varuint(height_payload.len() as u64, &mut out);
        out.extend_from_slice(&height_payload);
        out
    }

    #[test]
    fn test_committed_events_ots_detects_stale_digest_mismatch() {
        let ots_bytes = include_bytes!("../../../events.jsonl.ots");
        let events_bytes = include_bytes!("../../../events.jsonl");

        let parsed = parse_ots_proof(ots_bytes, events_bytes)
            .expect("committed events.jsonl.ots must parse cleanly");
        assert!(!parsed.digest_matches);
        assert_eq!(
            parsed.attested_sha256,
            "571e3f633093538496842c7f995dc9a13dde4886bdf38bdc34202a2aa1f6a4af"
        );
        assert_eq!(parsed.bitcoin_blocks, vec![971952, 971954, 971961]);
        assert_eq!(parsed.pending_calendars.len(), 3);

        let err = verify_ots_bytes(ots_bytes, events_bytes).unwrap_err();
        assert!(matches!(err, OtsError::DigestMismatch { .. }));
    }

    #[test]
    fn test_synthetic_ots_verifies_matching_bytes_and_rejects_tamper() {
        let target = b"{\"size\":5,\"head_hash\":\"abc\"}";
        let ots = build_synthetic_ots(target, 972_000);

        let report = verify_ots_bytes(&ots, target).expect("matching digest must verify");
        assert!(report.digest_matches);
        assert_eq!(report.bitcoin_blocks, vec![972_000]);

        let tampered = b"{\"size\":5,\"head_hash\":\"abd\"}";
        let err = verify_ots_bytes(&ots, tampered).unwrap_err();
        assert!(matches!(err, OtsError::DigestMismatch { .. }));
    }

    #[test]
    fn test_rejects_bad_magic_and_truncated_proof() {
        let target = b"hello";
        let mut ots = build_synthetic_ots(target, 900_000);
        ots[0] = 0x55;
        assert_eq!(
            verify_ots_bytes(&ots, target).unwrap_err(),
            OtsError::InvalidMagic
        );

        let good = build_synthetic_ots(target, 900_000);
        let truncated = &good[..good.len() - 2];
        assert!(matches!(
            verify_ots_bytes(truncated, target).unwrap_err(),
            OtsError::MalformedProof(_)
        ));
    }
}
