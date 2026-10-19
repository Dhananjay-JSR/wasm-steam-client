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
use steam_vent_proto_steam::steammessages_auth_steamclient::{
    CAuthentication_GetPasswordRSAPublicKey_Request, CAuthentication_GetPasswordRSAPublicKey_Response,
};
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

/// Report every leaf frame in a received WebSocket message (Multi expanded).
fn handle_message(cb: &Function, data: &[u8]) {
    for f in codec::flatten(data) {
        if f.emsg == EMsg::k_EMsgClientLogOnResponse.value() as u32 {
            match CMsgClientLogonResponse::parse_from_bytes(&f.body) {
                Ok(r) => log(cb, &format!(
                    "✅ ClientLogOnResponse eresult={} (1=OK) — transport+framing confirmed",
                    r.eresult()
                )),
                Err(err) => log(cb, &format!("logon response parse error: {err:?}")),
            }
        } else {
            log(cb, &format!("recv EMsg={} ({} body bytes)", f.emsg, f.body.len()));
        }
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
        handle_message(&cb, &data);
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    attach_status(&ws, &log_cb);
    Ok(())
}

/// Wire up error/close logging on a socket (shared by every harness entry point).
fn attach_status(ws: &WebSocket, log_cb: &Function) {
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
}

/// M3.1 — fetch the account's RSA public key via the Authentication service
/// (`Authentication.GetPasswordRSAPublicKey#1`, a NonAuthed ServiceMethod RPC).
/// Needs only the account **name**, no password; proves the authenticated RPC layer
/// and returns the key we'll encrypt the password against in M3.2.
#[wasm_bindgen]
pub fn get_rsa_key(url: &str, account_name: &str, log_cb: Function) -> Result<(), JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    log(&log_cb, &format!("connecting to {url} …"));

    let account = account_name.to_string();
    let ws_send = ws.clone();
    let cb = log_cb.clone();
    let onopen = Closure::<dyn FnMut()>::new(move || {
        let mut header = CMsgProtoBufHeader::new();
        header.set_target_job_name("Authentication.GetPasswordRSAPublicKey#1".to_string());
        header.set_jobid_source(1);
        // NonAuthed service calls require realm=1 and an explicit steamid=0, else the CM drops them.
        header.set_realm(1);
        header.set_steamid(0);
        let mut req = CAuthentication_GetPasswordRSAPublicKey_Request::new();
        req.set_account_name(account.clone());
        let body = req.write_to_bytes().unwrap_or_default();
        let emsg = EMsg::k_EMsgServiceMethodCallFromClientNonAuthed.value() as u32;
        match codec::encode(emsg, &header, &body) {
            Ok(frame) => {
                log(&cb, &format!("requesting RSA key for '{account}' …"));
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
        for f in codec::flatten(&data) {
            if f.emsg != EMsg::k_EMsgServiceMethodResponse.value() as u32 {
                log(&cb, &format!("recv EMsg={}", f.emsg));
                continue;
            }
            let eresult = f.header.eresult.unwrap_or(1);
            if eresult != 1 {
                log(&cb, &format!("❌ service response eresult={eresult} ({})", f.header.error_message()));
                continue;
            }
            match CAuthentication_GetPasswordRSAPublicKey_Response::parse_from_bytes(&f.body) {
                Ok(r) => {
                    let m = r.publickey_mod();
                    let preview = &m[..m.len().min(32)];
                    log(&cb, &format!(
                        "✅ RSA key: {}-bit mod {preview}… exp={} ts={}",
                        m.len() * 4, r.publickey_exp(), r.timestamp()
                    ));
                }
                Err(err) => log(&cb, &format!("rsa response parse error: {err:?}")),
            }
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    attach_status(&ws, &log_cb);
    Ok(())
}
