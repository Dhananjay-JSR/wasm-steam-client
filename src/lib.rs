//! A Steam **Connection Manager (CM) protocol** client intended to run in the
//! browser via WASM. It speaks the same wire protocol as the regular Steam
//! client — over a `wss://` WebSocket — to log in (your own account) and, in a
//! later milestone, mint a Web API auth ticket. No local Steam install, no
//! `steam_api64.dll`.
//!
//! Scope boundary (see the project README): this is for **your own account**.
//! Logging in means your Steam credentials + Steam Guard are entered in the
//! page, exactly as the native CM login does it — fine for a personal tool,
//! never for collecting anyone else's credentials.
//!
//! This module is `codec`: the wire framing every CM message uses. It is pure
//! (no I/O), so it unit-tests on the host and compiles unchanged to wasm32.

pub mod codec;
