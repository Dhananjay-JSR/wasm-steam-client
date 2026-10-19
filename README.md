# wasm-steam-client

A **Steam Connection Manager (CM) protocol client that runs in the browser (WASM)**, in Rust.
It speaks the same wire protocol as the regular Steam client over a `wss://` WebSocket — so it can
log in and (goal) mint a **Web API auth ticket** for an app, with **no local Steam install and no
`steam_api64.dll`**.

## Scope and boundary (read this)

This is a **personal, own-account tool**. Logging in over the CM protocol means your Steam
credentials + Steam Guard are entered **in the page**, exactly as the native CM client login does it.
That is fine for a tool that only ever touches **your own** account; it is **not** acceptable to
collect anyone else's credentials, and shipping it as a multi-user service would make it a credential
honeypot. It is also a Steam-ToS question that falls on you — same as any SteamKit2 / `node-steam-user`
based tool, which this is the Rust/WASM equivalent of.

What it deliberately does **not** do: the ARC Raiders / Embark exchange (that needs first-party game
credentials lifted from the game client and is out of scope).

## Why WASM can do this (but not the Steamworks SDK)

Two different ways exist to get a Steam ticket:

- **Steamworks SDK** (`GetAuthTicketForWebApi`) talks to the *local running Steam client* over native
  IPC — a browser sandbox can't reach it. Out of scope.
- **CM protocol** (this project) is a from-scratch client that connects to Steam's servers over a
  network socket. CM speaks WebSocket (`wss://`), and a browser can open those — so a WASM module can
  run the whole login itself, no local client involved. This is what `node-steam-user` / SteamKit2 do.

## Architecture

- **Protobuf message types** are reused from steam-vent's generated crates
  (`steam-vent-proto-steam`, `-common`) — pure Rust, so they compile to wasm32. We do **not**
  regenerate the protocol.
- **Transport** is the browser's own WebSocket API (`web-sys`) — steam-vent's tokio/rustls transport
  can't run in a browser, so this is the new code.
- **`codec`** is the CM wire framing: `[u32 emsg|PROTO_MASK][u32 header_len][CMsgProtoBufHeader][body]`.
  Pure, unit-tested, shared by every message.

## Milestones

- [x] **M1 — framing codec** + repo + wasm32 build. Pure, unit-tested.
- [ ] **M2 — browser WebSocket transport** + anonymous CM logon, verified in a real browser
  (the live protocol check — needs a browser, can't be unit-tested from CI).
- [ ] **M3 — credentialed login**: `GetPasswordRSAPublicKey` → RSA-encrypt password →
  `BeginAuthSessionViaCredentials` → Steam Guard → refresh token → CM logon.
- [ ] **M4 — mint the Web API auth ticket** for an appid (the RPC no Rust crate exposes yet).

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo test                                   # host-side logic (codec)
cargo build --target wasm32-unknown-unknown  # browser build
```
