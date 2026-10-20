# wasm-steam-client

A **Steam client that runs entirely in a browser tab**, written in Rust and compiled to WASM.
It speaks the real Steam **Connection Manager (CM) protocol** over a `wss://` WebSocket — the same
wire protocol the desktop client uses — so it can **log in** (QR or password) and **mint a Web API
auth ticket** for any app you own, with **no local Steam install and no `steam_api64.dll`**.

It is the Rust/WASM equivalent of what `node-steam-user` / SteamKit2 do natively — but it needs
nothing installed; it's a web page.

## What works today

| Milestone | Capability |
|---|---|
| **M1** | CM wire-framing codec (`[u32 emsg\|PROTO_MASK][u32 header_len][CMsgProtoBufHeader][body]`), Multi-envelope unwrap (gunzip), frame flatten |
| **M2** | Browser WebSocket transport + anonymous CM logon (the live-protocol proof) |
| **M3.1** | `GetPasswordRSAPublicKey` over the authenticated-service RPC layer |
| **M3.2** | Password login — RSA-encrypt the password in-browser → `BeginAuthSessionViaCredentials` |
| **M3 (QR)** | **QR login, no password** — `BeginAuthSessionViaQR` → scan with the Steam mobile app → poll → refresh token |
| **M4** | **Mint a Web API auth ticket** for any owned appid — token logon → GC token + app-ownership ticket → build + activate via `ClientAuthList` → final hex ticket, validated by Steam (`ClientTicketAuthComplete`) |

The minted hex ticket validates server-side with
`ISteamUserAuth/AuthenticateUserTicket` (returns your SteamID64).

## Scope and boundary (read this)

This is a **personal, own-account tool.** Logging in over the CM protocol means your Steam
credentials / QR approval happen **in the page**, exactly as the native CM client login does it. That
is fine for a tool that only ever touches **your own** account; it is **not** acceptable to collect
anyone else's credentials, and shipping it as a multi-user service would make it a credential
honeypot. It is a Steam-ToS question that falls on you — the same one every SteamKit2 / `node-steam-user`
tool lives with.

It deliberately does **not** do the ARC Raiders / Embark exchange — that needs first-party game
credentials lifted from the game client and is out of scope.

## Why WASM can do this (but the Steamworks SDK can't)

There are two different ways to get a Steam ticket:

- **Steamworks SDK** (`GetAuthTicketForWebApi`) talks to the *local running Steam client* over native
  IPC — a browser sandbox can't reach it. Out of scope, and impossible from a tab.
- **CM protocol** (this project) is a from-scratch client that connects to Steam's servers over a
  network socket. CM speaks WebSocket (`wss://`), and a browser can open those — so a WASM module runs
  the whole login itself, no local client involved.

## Architecture

- **`codec`** — the CM wire framing: encode/decode, Multi unwrap, flatten. Pure, unit-tested, shared
  by every message.
- **`auth`** — pure crypto/helpers: RSA password encryption (PKCS#1 v1.5), SteamID-from-JWT, and the
  auth-ticket byte assembly. Unit-tested on the host.
- **`transport`** (wasm32 only) — the browser's own WebSocket API (`web-sys`). steam-vent's
  tokio/rustls transport can't run in a browser, so this is the new code: the `#[wasm_bindgen]`
  entry points (`anon_logon`, `begin_qr`/`poll_qr`, `begin_login`, `mint_ticket`), the ClientHello
  preamble, the authenticated/NonAuthed ServiceMethod RPC layer, and the ticket flow.
- **Protobuf message types** are reused from steam-vent's generated crates
  (`steam-vent-proto-steam`, `-common`) — pure Rust, so they compile to wasm32. We do **not**
  regenerate the protocol, only the transport and the flows on top of it.

## Build & run

```sh
rustup target add wasm32-unknown-unknown
cargo test                        # host-side logic (codec + auth), 8 tests
wasm-pack build --target web      # emits pkg/
python3 -m http.server 8080       # serve the repo root
# open http://localhost:8080/web/
```

In the page (order matters — the token lives in page memory):

1. **M2 · anon-logon** — proves the transport (no account).
2. **M3 · Log in with QR** — scan the QR with the Steam mobile app, approve → refresh token stored.
3. Enter an **App ID you own** → **M4 · Mint Web API ticket** → prints the hex ticket and Steam's
   validation result.

If the CM host in the URL is stale (`ws closed` immediately), grab a fresh one:

```sh
curl "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cmtype=websockets&cellid=0"
# then use  wss://<endpoint>/cmsocket/
```

> **Toolchain note:** this project needs rustup's toolchain (Homebrew's Rust has no wasm32 std). If
> `cargo`/`wasm-pack` resolve to Homebrew after a shell restart, prefix with
> `export PATH="$HOME/.cargo/bin:$PATH"`.

## Security notes

- Your **password is RSA-encrypted inside the WASM module** before anything is sent; the cleartext
  never leaves the tab. QR login sends no password at all.
- The **refresh token and the minted ticket are real credentials for your account.** The harness only
  prints truncated previews of the token; treat even those as sensitive.

## Not a partnership

This reproduces the Steam client's own protocol. Steam can change it at any time, and a third-party
client is restricted by the Steam Subscriber Agreement. Use it for your own account, at your own risk.
