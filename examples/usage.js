// Example: using wasm-steam-client in a JS project.
//
// The crate is built with `wasm-pack build --target web`, which emits an ES-module
// package in `pkg/`. Import it, call the default `init()` once, then use the exported
// functions. Their API streams progress as strings through a callback; the helpers
// below wrap that into Promises you can `await`.
//
//   import init, { begin_qr, poll_qr, mint_ticket, has_token } from "wasm-steam-client";
//   (or from a relative path: "../pkg/wasm_steam_client.js")

import init, { begin_qr, poll_qr, mint_ticket, has_token } from "../pkg/wasm_steam_client.js";

// A Steam CM WebSocket endpoint: wss://<host>/cmsocket/.
// NOTE: the CM list lives at ISteamDirectory/GetCMListForConnect, but that endpoint is
// CORS-blocked from a browser — so hardcode a known host, refresh it occasionally, or
// proxy that one request through your own backend. The WebSocket connection itself is
// not subject to CORS.
const CM_URL = "wss://ext1-maa2.steamserver.net:27031/cmsocket/";

/** Log in by QR. `onQr(svg)` is called with an inline SVG QR to render; the user scans
 *  it with the Steam mobile app. Resolves with the account name once approved. */
export function qrLogin(onQr, cmUrl = CM_URL) {
  return new Promise((resolve, reject) => {
    let timer = null;
    const done = (fn) => { if (timer) clearInterval(timer); fn(); };
    begin_qr(
      cmUrl,
      (msg) => {
        console.debug("[steam]", msg);
        const m = msg.match(/logged in as (\S+)!/);
        if (m) return done(() => resolve(m[1]));
        if (msg.includes("expired")) return done(() => reject(new Error("QR expired — retry")));
      },
      onQr, // receives the QR as an SVG string
    );
    timer = setInterval(poll_qr, 2500); // poll Steam until the scan is approved
  });
}

/** Mint a Web API auth ticket for `appId` (you must be logged in and own the app).
 *  Resolves with the ticket as a hex string. */
export function mintTicket(appId, cmUrl = CM_URL) {
  if (!has_token()) return Promise.reject(new Error("log in first (qrLogin)"));
  return new Promise((resolve, reject) => {
    let hexNext = false;
    mint_ticket(cmUrl, appId, (msg) => {
      console.debug("[steam]", msg);
      if (hexNext) return resolve(msg.trim()); // the line right after "(hex):"
      if (msg.includes("(hex):")) hexNext = true;
      if (msg.startsWith("❌")) reject(new Error(msg));
    });
  });
}

// --- putting it together ---
async function main() {
  await init(); // load the wasm module once

  const account = await qrLogin((svg) => {
    document.getElementById("qr").innerHTML = svg; // show the QR to scan
  });
  console.log("logged in as", account);

  const ticket = await mintTicket(1808500); // appid you own
  console.log("web api auth ticket (hex):", ticket);

  // Validate it server-side (needs your Web API key — do this on YOUR backend, not here):
  //   GET https://api.steampowered.com/ISteamUserAuth/AuthenticateUserTicket/v1/
  //       ?key=<WEB_API_KEY>&appid=1808500&ticket=<ticket>
  //   → returns your SteamID64 if valid.
}

main().catch(console.error);
