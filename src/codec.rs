//! Steam CM message framing.
//!
//! Every modern CM message on the wire is one binary WebSocket frame shaped as:
//!
//! ```text
//! [ u32 LE emsg | PROTO_MASK ] [ u32 LE header_len ] [ header_len bytes: CMsgProtoBufHeader ] [ body ]
//! ```
//!
//! The high bit of the first word (`PROTO_MASK`) flags a protobuf message; the
//! low 31 bits are the `EMsg`. The header carries routing/session fields
//! (`steamid`, `client_sessionid`, `jobid_source`/`jobid_target`); the body is
//! the message-specific protobuf.

use protobuf::Message;
use steam_vent_proto_steam::steammessages_base::{CMsgMulti, CMsgProtoBufHeader};

/// EMsg of a Multi envelope: Steam bundles one or more replies inside it.
pub const EMSG_MULTI: u32 = 1;

/// High bit of the EMsg word marking a protobuf (vs. legacy struct) message.
pub const PROTO_MASK: u32 = 0x8000_0000;

#[derive(Debug)]
pub enum CodecError {
    /// Frame shorter than the 8-byte emsg+header-length prefix, or truncated header/body.
    Truncated,
    /// EMsg word lacked the protobuf flag. This client only speaks protobuf messages.
    NotProtobuf,
    /// The header bytes didn't parse as a CMsgProtoBufHeader.
    BadHeader(protobuf::Error),
    /// A Multi body (or its gzip payload) was malformed.
    BadMulti,
}

/// A decoded CM message: its `EMsg` (low 31 bits), the proto header, and the raw body.
#[derive(Debug)]
pub struct Frame {
    pub emsg: u32,
    pub header: CMsgProtoBufHeader,
    pub body: Vec<u8>,
}

/// Encode a CM message to a WebSocket binary frame. `body` is the already-serialized
/// message-specific protobuf.
pub fn encode(emsg: u32, header: &CMsgProtoBufHeader, body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let header_bytes = header.write_to_bytes().map_err(CodecError::BadHeader)?;
    let mut out = Vec::with_capacity(8 + header_bytes.len() + body.len());
    out.extend_from_slice(&(emsg | PROTO_MASK).to_le_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(body);
    Ok(out)
}

/// Decode a WebSocket binary frame into its EMsg, header and body.
pub fn decode(data: &[u8]) -> Result<Frame, CodecError> {
    if data.len() < 8 {
        return Err(CodecError::Truncated);
    }
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if raw & PROTO_MASK == 0 {
        return Err(CodecError::NotProtobuf);
    }
    let emsg = raw & !PROTO_MASK;
    let header_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let header_end = 8usize.checked_add(header_len).ok_or(CodecError::Truncated)?;
    if data.len() < header_end {
        return Err(CodecError::Truncated);
    }
    let header =
        CMsgProtoBufHeader::parse_from_bytes(&data[8..header_end]).map_err(CodecError::BadHeader)?;
    let body = data[header_end..].to_vec();
    Ok(Frame { emsg, header, body })
}

/// Unwrap a Multi (EMsg 1) body into the inner message frames it carries. Each inner
/// frame is a full CM frame (feed it back to [`decode`]). The payload is gunzipped first
/// when `size_unzipped` is set.
pub fn unwrap_multi(multi_body: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
    use std::io::Read;
    let multi = CMsgMulti::parse_from_bytes(multi_body).map_err(CodecError::BadHeader)?;
    let payload = if multi.size_unzipped() > 0 {
        let mut out = Vec::with_capacity(multi.size_unzipped() as usize);
        flate2::read::GzDecoder::new(multi.message_body())
            .read_to_end(&mut out)
            .map_err(|_| CodecError::BadMulti)?;
        out
    } else {
        multi.message_body().to_vec()
    };

    // payload is a run of [u32 LE len][len bytes] records.
    let mut frames = Vec::new();
    let mut i = 0usize;
    while i + 4 <= payload.len() {
        let len =
            u32::from_le_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]) as usize;
        i += 4;
        let end = i.checked_add(len).ok_or(CodecError::BadMulti)?;
        if end > payload.len() {
            return Err(CodecError::BadMulti);
        }
        frames.push(payload[i..end].to_vec());
        i = end;
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::Enum;
    use steam_vent_proto_steam::enums_clientserver::EMsg;

    #[test]
    fn roundtrip_preserves_emsg_header_and_body() {
        // .value() is the real wire number (5514); `as u32` would be the Rust discriminant.
        let emsg = EMsg::k_EMsgClientLogon.value() as u32;
        assert_eq!(emsg, 5514);
        let mut header = CMsgProtoBufHeader::new();
        header.set_steamid(76561198000000001);
        header.set_client_sessionid(42);
        header.set_jobid_source(7);
        let body = vec![1u8, 2, 3, 4, 5];

        let wire = encode(emsg, &header, &body).unwrap();
        // high bit set -> protobuf flag present on the wire
        let raw = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]);
        assert_eq!(raw & PROTO_MASK, PROTO_MASK);
        assert_eq!(raw & !PROTO_MASK, emsg);

        let f = decode(&wire).unwrap();
        assert_eq!(f.emsg, emsg);
        assert_eq!(f.header.steamid(), 76561198000000001);
        assert_eq!(f.header.client_sessionid(), 42);
        assert_eq!(f.header.jobid_source(), 7);
        assert_eq!(f.body, body);
    }

    #[test]
    fn unwrap_multi_splits_inner_frames() {
        // build an uncompressed Multi carrying two inner frames
        let f1 = encode(751, &CMsgProtoBufHeader::new(), &[9, 9]).unwrap();
        let f2 = encode(5514, &CMsgProtoBufHeader::new(), &[7]).unwrap();
        let mut payload = Vec::new();
        for f in [&f1, &f2] {
            payload.extend_from_slice(&(f.len() as u32).to_le_bytes());
            payload.extend_from_slice(f);
        }
        let mut multi = CMsgMulti::new();
        multi.set_size_unzipped(0); // 0 == not gzipped
        multi.set_message_body(payload);
        let multi_body = multi.write_to_bytes().unwrap();

        let inner = unwrap_multi(&multi_body).unwrap();
        assert_eq!(inner.len(), 2);
        assert_eq!(decode(&inner[0]).unwrap().emsg, 751);
        assert_eq!(decode(&inner[1]).unwrap().body, vec![7]);
    }

    #[test]
    fn rejects_non_protobuf_and_truncated() {
        // no proto flag
        let mut no_flag = 751u32.to_le_bytes().to_vec();
        no_flag.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(decode(&no_flag), Err(CodecError::NotProtobuf)));

        // header_len claims more bytes than present
        let mut bad = (5514u32 | PROTO_MASK).to_le_bytes().to_vec();
        bad.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(decode(&bad), Err(CodecError::Truncated)));

        assert!(matches!(decode(&[0u8; 3]), Err(CodecError::Truncated)));
    }
}
