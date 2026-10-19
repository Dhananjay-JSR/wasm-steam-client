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
use crate::auth::{encrypt_password, steamid_from_jwt};
use protobuf::MessageField;
use std::cell::RefCell;
use steam_vent_proto_steam::steammessages_base::CMsgIPAddress;
use steam_vent_proto_steam::steammessages_clientserver::{
    CMsgClientGameConnectTokens, CMsgClientGetAppOwnershipTicket,
    CMsgClientGetAppOwnershipTicketResponse,
};
use steam_vent_proto_steam::enums::ESessionPersistence;
use steam_vent_proto_steam::steammessages_auth_steamclient::{
    CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_BeginAuthSessionViaCredentials_Response,
    CAuthentication_BeginAuthSessionViaQR_Request, CAuthentication_BeginAuthSessionViaQR_Response,
    CAuthentication_DeviceDetails, CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_GetPasswordRSAPublicKey_Response,
    CAuthentication_PollAuthSessionStatus_Request, CAuthentication_PollAuthSessionStatus_Response,
    EAuthTokenPlatformType,
};
use steam_vent_proto_steam::steammessages_clientserver_login::{
    CMsgClientHello, CMsgClientLogon, CMsgClientLogonResponse,
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

/// Send the ClientHello the CM expects first, so it learns our protocol version
/// before we make bare (non-logon) service calls. Fire-and-forget (no reply).
fn send_hello(ws: &WebSocket) {
    let mut body = CMsgClientHello::new();
    body.set_protocol_version(PROTOCOL_VERSION);
    let bytes = body.write_to_bytes().unwrap_or_default();
    if let Ok(frame) = codec::encode(EMsg::k_EMsgClientHello.value() as u32, &CMsgProtoBufHeader::new(), &bytes) {
        let _ = ws.send_with_u8_array(&frame);
    }
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

/// The in-progress QR session, held so `poll_qr` (driven by a JS timer) can reuse the
/// same socket and the client_id/request_id the Begin response gave us.
struct QrSession {
    ws: WebSocket,
    client_id: u64,
    request_id: Vec<u8>,
}
thread_local! {
    static QR: RefCell<Option<QrSession>> = const { RefCell::new(None) };
    /// The refresh token from a successful login, kept for M4 (ticket minting).
    static REFRESH_TOKEN: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// The refresh token from the last successful login (for debugging / M4 wiring).
#[wasm_bindgen]
pub fn has_token() -> bool {
    REFRESH_TOKEN.with(|t| t.borrow().is_some())
}

/// Render a challenge URL as an inline SVG QR code.
fn render_qr(data: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .build())
}

/// M3 (QR) — log in by QR, no password. Fetches a QR challenge, renders it via `qr_cb`,
/// and stores the session so `poll_qr` can poll for approval. Scan it with the Steam
/// mobile app; `poll_qr` then returns your refresh token.
#[wasm_bindgen]
pub fn begin_qr(url: &str, log_cb: Function, qr_cb: Function) -> Result<(), JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    log(&log_cb, &format!("connecting to {url} …"));
    QR.with(|q| {
        *q.borrow_mut() = Some(QrSession { ws: ws.clone(), client_id: 0, request_id: Vec::new() })
    });

    let ws_open = ws.clone();
    let cb = log_cb.clone();
    let onopen = Closure::<dyn FnMut()>::new(move || {
        send_hello(&ws_open);
        let mut details = CAuthentication_DeviceDetails::new();
        details.set_device_friendly_name("wasm-steam-client".to_string());
        details.set_platform_type(EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient);
        let mut req = CAuthentication_BeginAuthSessionViaQR_Request::new();
        req.set_website_id("Client".to_string());
        req.device_details = MessageField::some(details);
        service_call(
            &ws_open,
            "Authentication.BeginAuthSessionViaQR#1",
            1,
            &req.write_to_bytes().unwrap_or_default(),
        );
        log(&cb, "requesting QR challenge …");
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    onopen.forget();

    let cb = log_cb.clone();
    let qcb = qr_cb.clone();
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let data = js_sys::Uint8Array::new(&e.data()).to_vec();
        for f in codec::flatten(&data) {
            if f.emsg != EMsg::k_EMsgServiceMethodResponse.value() as u32 {
                continue;
            }
            let eresult = f.header.eresult.unwrap_or(1);
            match f.header.jobid_target() {
                1 => {
                    if eresult != 1 {
                        log(&cb, &format!("❌ begin QR eresult={eresult}"));
                        continue;
                    }
                    let Ok(r) = CAuthentication_BeginAuthSessionViaQR_Response::parse_from_bytes(&f.body) else { continue };
                    QR.with(|q| {
                        if let Some(s) = q.borrow_mut().as_mut() {
                            s.client_id = r.client_id();
                            s.request_id = r.request_id().to_vec();
                        }
                    });
                    match render_qr(r.challenge_url()) {
                        Ok(svg) => {
                            let _ = qcb.call1(&JsValue::NULL, &JsValue::from_str(&svg));
                            log(&cb, "scan the QR with your Steam mobile app, then approve …");
                        }
                        Err(e) => log(&cb, &format!("qr render error: {e}")),
                    }
                }
                2 => {
                    if eresult != 1 {
                        log(&cb, &format!("❌ poll eresult={eresult} ({}) — QR likely expired, restart", f.header.error_message()));
                        QR.with(|q| *q.borrow_mut() = None);
                        continue;
                    }
                    let Ok(r) = CAuthentication_PollAuthSessionStatus_Response::parse_from_bytes(&f.body) else { continue };
                    if !r.refresh_token().is_empty() {
                        let t = r.refresh_token();
                        REFRESH_TOKEN.with(|rt| *rt.borrow_mut() = Some(t.to_string()));
                        log(&cb, &format!(
                            "✅ approved — logged in as {}! refresh_token: {}… ({} chars)",
                            r.account_name(), &t[..t.len().min(24)], t.len()
                        ));
                        log(&cb, "token stored — ready to mint a ticket (M4).");
                        QR.with(|q| *q.borrow_mut() = None);
                    } else {
                        if r.had_remote_interaction() {
                            log(&cb, "scanned — waiting for you to approve in the app …");
                        }
                        QR.with(|q| {
                            if let Some(s) = q.borrow_mut().as_mut() {
                                if r.new_client_id() != 0 {
                                    s.client_id = r.new_client_id();
                                }
                            }
                        });
                        if !r.new_challenge_url().is_empty() {
                            if let Ok(svg) = render_qr(r.new_challenge_url()) {
                                let _ = qcb.call1(&JsValue::NULL, &JsValue::from_str(&svg));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    attach_status(&ws, &log_cb);
    Ok(())
}

/// Poll the QR auth session once (JS calls this on an interval until approval).
#[wasm_bindgen]
pub fn poll_qr() {
    QR.with(|q| {
        if let Some(s) = q.borrow().as_ref() {
            if s.request_id.is_empty() {
                return; // challenge not received yet
            }
            let mut req = CAuthentication_PollAuthSessionStatus_Request::new();
            req.set_client_id(s.client_id);
            req.set_request_id(s.request_id.clone());
            service_call(
                &s.ws,
                "Authentication.PollAuthSessionStatus#1",
                2,
                &req.write_to_bytes().unwrap_or_default(),
            );
        }
    });
}

/// An authenticated CM session (after token logon), holding the ingredients the
/// Web API auth ticket is built from.
struct Session {
    ws: WebSocket,
    steamid: u64,
    session_id: i32,
    public_ip: u32,
    app_id: u32,
    gc_tokens: Vec<Vec<u8>>,
    ownership_ticket: Vec<u8>,
}
thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Send a regular (authenticated) client message, stamping steamid + session id.
fn client_send(ws: &WebSocket, emsg: u32, steamid: u64, session_id: i32, body: &[u8]) {
    let mut h = CMsgProtoBufHeader::new();
    h.set_steamid(steamid);
    h.set_client_sessionid(session_id);
    if let Ok(frame) = codec::encode(emsg, &h, body) {
        let _ = ws.send_with_u8_array(&frame);
    }
}

/// M4 (part A) — log onto the CM with the stored refresh token (as *you*), then
/// gather the two ingredients a Web API auth ticket needs for `app_id`: a GC token
/// (pushed by Steam after logon) and the app ownership ticket. Building + activating
/// the ticket is part B.
#[wasm_bindgen]
pub fn mint_ticket(url: &str, app_id: u32, log_cb: Function) -> Result<(), JsValue> {
    let token = match REFRESH_TOKEN.with(|t| t.borrow().clone()) {
        Some(t) => t,
        None => {
            log(&log_cb, "no token yet — log in with QR first.");
            return Ok(());
        }
    };
    let steamid = match steamid_from_jwt(&token) {
        Some(s) => s,
        None => {
            log(&log_cb, "could not read SteamID from the token.");
            return Ok(());
        }
    };

    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    log(&log_cb, &format!("connecting to {url} to mint a ticket for app {app_id} …"));
    SESSION.with(|s| {
        *s.borrow_mut() = Some(Session {
            ws: ws.clone(),
            steamid,
            session_id: 0,
            public_ip: 0,
            app_id,
            gc_tokens: Vec::new(),
            ownership_ticket: Vec::new(),
        })
    });

    let ws_open = ws.clone();
    let cb = log_cb.clone();
    let onopen = Closure::<dyn FnMut()>::new(move || {
        send_hello(&ws_open);
        let mut ip = CMsgIPAddress::new();
        ip.set_v4(0);
        let mut logon = CMsgClientLogon::new();
        logon.set_protocol_version(PROTOCOL_VERSION);
        logon.set_client_os_type(203);
        logon.set_supports_rate_limit_response(false);
        logon.obfuscated_private_ip = MessageField::some(ip);
        logon.set_client_language(String::new());
        logon.set_machine_name(String::new());
        logon.set_steamguard_dont_remember_computer(false);
        logon.set_chat_mode(2);
        logon.set_access_token(token.clone());
        logon.set_client_package_version(1771);
        client_send(&ws_open, EMsg::k_EMsgClientLogon.value() as u32, steamid, 0,
            &logon.write_to_bytes().unwrap_or_default());
        log(&cb, "logging in with your refresh token …");
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    onopen.forget();

    let cb = log_cb.clone();
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let data = js_sys::Uint8Array::new(&e.data()).to_vec();
        for f in codec::flatten(&data) {
            let emsg = f.emsg;
            if emsg == EMsg::k_EMsgClientLogOnResponse.value() as u32 {
                let Ok(r) = CMsgClientLogonResponse::parse_from_bytes(&f.body) else { continue };
                if r.eresult() != 1 {
                    log(&cb, &format!("❌ logon eresult={} — token may be expired, log in again", r.eresult()));
                    continue;
                }
                let session_id = f.header.client_sessionid();
                let public_ip = r.public_ip.ip.as_ref().and_then(|ip| match ip {
                    steam_vent_proto_steam::steammessages_base::cmsg_ipaddress::Ip::V4(b) => Some(*b),
                    _ => None,
                }).unwrap_or(0);
                SESSION.with(|s| if let Some(s) = s.borrow_mut().as_mut() {
                    s.session_id = session_id;
                    s.public_ip = public_ip;
                });
                log(&cb, &format!("✅ logged in as you (steamid={steamid}, session={session_id}); requesting app ownership ticket …"));
                let (ws, app_id) = SESSION.with(|s| {
                    let b = s.borrow();
                    let s = b.as_ref().unwrap();
                    (s.ws.clone(), s.app_id)
                });
                let mut req = CMsgClientGetAppOwnershipTicket::new();
                req.set_app_id(app_id);
                client_send(&ws, EMsg::k_EMsgClientGetAppOwnershipTicket.value() as u32, steamid, session_id,
                    &req.write_to_bytes().unwrap_or_default());
            } else if emsg == EMsg::k_EMsgClientGameConnectTokens.value() as u32 {
                let Ok(r) = CMsgClientGameConnectTokens::parse_from_bytes(&f.body) else { continue };
                let n = r.tokens.len();
                SESSION.with(|s| if let Some(s) = s.borrow_mut().as_mut() {
                    s.gc_tokens.extend(r.tokens);
                });
                log(&cb, &format!("received {n} GC token(s)"));
                report_ready(&cb);
            } else if emsg == EMsg::k_EMsgClientGetAppOwnershipTicketResponse.value() as u32 {
                let Ok(r) = CMsgClientGetAppOwnershipTicketResponse::parse_from_bytes(&f.body) else { continue };
                if r.eresult() != 1 {
                    log(&cb, &format!("❌ app ownership ticket eresult={} (do you own app {}?)", r.eresult(), r.app_id()));
                    continue;
                }
                let len = r.ticket().len();
                SESSION.with(|s| if let Some(s) = s.borrow_mut().as_mut() {
                    s.ownership_ticket = r.ticket().to_vec();
                });
                log(&cb, &format!("received app ownership ticket ({len} bytes) for app {}", r.app_id()));
                report_ready(&cb);
            }
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    attach_status(&ws, &log_cb);
    Ok(())
}

/// Log when both ticket ingredients are in hand.
fn report_ready(cb: &Function) {
    SESSION.with(|s| {
        if let Some(s) = s.borrow().as_ref() {
            if !s.gc_tokens.is_empty() && !s.ownership_ticket.is_empty() {
                log(cb, "🧩 have GC token + ownership ticket — ready to build the Web API ticket (M4 part B).");
            }
        }
    });
}

/// Send a NonAuthed ServiceMethod call (realm=1, steamid=0, as the CM requires).
fn service_call(ws: &WebSocket, method: &str, jobid: u64, body: &[u8]) {
    let mut header = CMsgProtoBufHeader::new();
    header.set_target_job_name(method.to_string());
    header.set_jobid_source(jobid);
    header.set_realm(1);
    header.set_steamid(0);
    let emsg = EMsg::k_EMsgServiceMethodCallFromClientNonAuthed.value() as u32;
    if let Ok(frame) = codec::encode(emsg, &header, body) {
        let _ = ws.send_with_u8_array(&frame);
    }
}

/// M3.2 — begin a credentialed auth session. Fetches the RSA key, encrypts the
/// password in-browser, and calls `BeginAuthSessionViaCredentials`, then reports the
/// Steam Guard challenge (the allowed confirmation types). Approving the challenge and
/// polling for the token is M3.3.
#[wasm_bindgen]
pub fn begin_login(
    url: &str,
    account_name: &str,
    password: &str,
    log_cb: Function,
) -> Result<(), JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    log(&log_cb, &format!("connecting to {url} …"));

    let account = account_name.to_string();
    let ws_open = ws.clone();
    let cb = log_cb.clone();
    let acc_open = account.clone();
    let onopen = Closure::<dyn FnMut()>::new(move || {
        send_hello(&ws_open);
        let mut req = CAuthentication_GetPasswordRSAPublicKey_Request::new();
        req.set_account_name(acc_open.clone());
        service_call(
            &ws_open,
            "Authentication.GetPasswordRSAPublicKey#1",
            1,
            &req.write_to_bytes().unwrap_or_default(),
        );
        log(&cb, &format!("requesting RSA key for '{acc_open}' …"));
    });
    ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
    onopen.forget();

    let ws_msg = ws.clone();
    let cb = log_cb.clone();
    let password = password.to_string();
    let onmessage = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        let data = js_sys::Uint8Array::new(&e.data()).to_vec();
        for f in codec::flatten(&data) {
            if f.emsg != EMsg::k_EMsgServiceMethodResponse.value() as u32 {
                log(&cb, &format!("recv EMsg={}", f.emsg));
                continue;
            }
            let eresult = f.header.eresult.unwrap_or(1);
            match f.header.jobid_target() {
                1 => {
                    if eresult != 1 {
                        log(&cb, &format!("❌ RSA fetch eresult={eresult}"));
                        continue;
                    }
                    let r = match CAuthentication_GetPasswordRSAPublicKey_Response::parse_from_bytes(&f.body) {
                        Ok(r) => r,
                        Err(e) => { log(&cb, &format!("rsa parse error: {e:?}")); continue; }
                    };
                    match encrypt_password(r.publickey_mod(), r.publickey_exp(), &password) {
                        Ok(enc) => {
                            log(&cb, "password encrypted in-browser; starting auth session …");
                            let mut details = CAuthentication_DeviceDetails::new();
                            details.set_device_friendly_name("wasm-steam-client".to_string());
                            details.set_platform_type(
                                EAuthTokenPlatformType::k_EAuthTokenPlatformType_SteamClient,
                            );
                            let mut breq = CAuthentication_BeginAuthSessionViaCredentials_Request::new();
                            breq.set_account_name(account.clone());
                            breq.set_encrypted_password(enc);
                            breq.set_encryption_timestamp(r.timestamp());
                            breq.set_persistence(
                                ESessionPersistence::k_ESessionPersistence_Persistent,
                            );
                            breq.set_website_id("Client".to_string());
                            breq.device_details = MessageField::some(details);
                            service_call(
                                &ws_msg,
                                "Authentication.BeginAuthSessionViaCredentials#1",
                                2,
                                &breq.write_to_bytes().unwrap_or_default(),
                            );
                        }
                        Err(e) => log(&cb, &format!("encrypt error: {e}")),
                    }
                }
                2 => {
                    if eresult != 1 {
                        log(&cb, &format!("❌ begin auth eresult={eresult} ({})", f.header.error_message()));
                        continue;
                    }
                    let r = match CAuthentication_BeginAuthSessionViaCredentials_Response::parse_from_bytes(&f.body) {
                        Ok(r) => r,
                        Err(e) => { log(&cb, &format!("begin parse error: {e:?}")); continue; }
                    };
                    log(&cb, &format!(
                        "✅ auth session started — steamid={} client_id={}",
                        r.steamid(), r.client_id()
                    ));
                    log(&cb, &format!(
                        "request_id={} bytes; {} Steam Guard option(s):",
                        r.request_id().len(), r.allowed_confirmations.len()
                    ));
                    for c in &r.allowed_confirmations {
                        log(&cb, &format!("  • {:?} {}", c.confirmation_type(), c.associated_message()));
                    }
                }
                other => log(&cb, &format!("unexpected jobid_target={other}")),
            }
        }
    });
    ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    attach_status(&ws, &log_cb);
    Ok(())
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
        send_hello(&ws_send);
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
