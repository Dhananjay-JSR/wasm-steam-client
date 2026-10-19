//! Browser WebSocket transport (wasm32 only).
//!
//! steam-vent's transport is tokio/rustls and can't run in a browser, so this is
//! the new piece: connect to a Steam CM server over the browser's own `wss://`
//! WebSocket, send framed CM messages, receive framed replies.
//!
//! [`anon_logon`] is the Milestone-2 proof: open the socket, send an **anonymous**
//! ClientLogon (no credentials), and report whatever Steam frames back. Any decoded
//! ClientLogOnResponse — even a non-OK `eresult` — proves the transport + framing
//! round-trip against live Steam. Real credentialed login is Milestone 3.

use crate::codec;
use js_sys::Function;
use protobuf::{Enum, Message};
use steam_vent_proto_steam::enums_clientserver::EMsg;
use steam_vent_proto_steam::steammessages_base::CMsgProtoBufHeader;
use steam_vent_proto_steam::steammessages_clientserver_login::{
    CMsgClientLogon, CMsgClientLogonResponse,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

/// SteamID64 of an anonymous user: universe=Public(1), type=AnonUser(10), instance 0, id 0.
const ANON_USER_STEAMID: u64 = (1 << 56) | (10 << 52);
/// CM protocol version the current client reports.
const PROTOCOL_VERSION: u32 = 65580;

fn log(cb: &Function, msg: &str) {
    let _ = cb.call1(&JsValue::NULL, &JsValue::from_str(msg));
}

/// Decode one CM frame and report it. A Multi (EMsg 1) is unwrapped and its inner
/// frames handled too (one level — nested Multi is rare; shortcut: upgrade if seen).
fn handle_frame(cb: &Function, data: &[u8]) {
    match codec::decode(data) {
        Ok(f) if f.emsg == codec::EMSG_MULTI => match codec::unwrap_multi(&f.body) {
            Ok(inner) => {
                log(cb, &format!("Multi envelope: {} inner message(s)", inner.len()));
                for frame in inner {
                    handle_frame(cb, &frame);
                }
            }
            Err(err) => log(cb, &format!("multi unwrap error: {err:?}")),
        },
        Ok(f) if f.emsg == EMsg::k_EMsgClientLogOnResponse.value() as u32 => {
            match CMsgClientLogonResponse::parse_from_bytes(&f.body) {
                Ok(r) => log(cb, &format!(
                    "✅ ClientLogOnResponse eresult={} (1=OK) — transport+framing confirmed",
                    r.eresult()
                )),
                Err(err) => log(cb, &format!("logon response parse error: {err:?}")),
            }
        }
        Ok(f) => log(cb, &format!("recv EMsg={} ({} body bytes)", f.emsg, f.body.len())),
        Err(err) => log(cb, &format!("decode error: {err:?} ({} bytes)", data.len())),
    }
}

/// Open `url` (e.g. `wss://ext1-maa2.steamserver.net:27031/cmsocket/`), send an
/// anonymous ClientLogon, and report progress through `log_cb(msg: string)`.
#[wasm_bindgen]
pub fn anon_logon(url: &str, log_cb: Function) -> Result<(), JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    log(&log_cb, &format!("connecting to {url} …"));

    let ws_send = ws.clone();
    let cb = log_cb.clone();
    let onopen = Closure::<dyn FnMut()>::new(move || {
        let mut header = CMsgProtoBufHeader::new();
        header.set_steamid(ANON_USER_STEAMID);
        header.set_client_sessionid(0);
        let mut body = CMsgClientLogon::new();
        body.set_protocol_version(PROTOCOL_VERSION);
        let body_bytes = body.write_to_bytes().unwrap_or_default();
        match codec::encode(EMsg::k_EMsgClientLogon.value() as u32, &header, &body_bytes) {
            Ok(frame) => {
                log(&cb, &format!("open; sending anonymous ClientLogon ({} bytes)", frame.len()));
                if let Err(e) = ws_send.send_with_u8_array(&frame) {
                    log(&cb, &format!("send failed: {e:?}"));
                }
            }
            Err(e) => log(&cb, &format!("encode error: {e:?}")),
        }
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    onopen.forget();

    let cb = log_cb.clone();
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let data = js_sys::Uint8Array::new(&e.data()).to_vec();
        handle_frame(&cb, &data);
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    let cb = log_cb.clone();
    let onerror = Closure::<dyn FnMut(ErrorEvent)>::new(move |e: ErrorEvent| {
        log(&cb, &format!("ws error: {}", e.message()));
    });
    ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    onerror.forget();

    let cb = log_cb.clone();
    let onclose = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
        log(&cb, &format!("ws closed (code={}, reason={:?})", e.code(), e.reason()));
    });
    ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
    onclose.forget();

    Ok(())
}
