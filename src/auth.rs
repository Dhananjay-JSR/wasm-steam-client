//! Password encryption for the Steam auth flow.
//!
//! Steam returns a per-account RSA public key (`GetPasswordRSAPublicKey`); the
//! password is PKCS#1 v1.5-encrypted against it and base64-encoded before it's
//! sent in `BeginAuthSessionViaCredentials`. The plaintext password never leaves
//! the browser.

use base64::prelude::{Engine, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use rand::rngs::OsRng;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

/// Pull the SteamID64 out of a refresh/access token JWT (the `sub` claim). Steam's
/// tokens are unsigned-readable JWTs; the authenticated logon needs this in the header.
pub fn steamid_from_jwt(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let json = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    // find "sub":"<digits>"
    let after_key = &json[json.find("\"sub\"")? + 5..];
    let start = after_key.find('"')? + 1;
    let end = after_key[start..].find('"')? + start;
    after_key[start..end].parse().ok()
}

/// Encrypt `password` with the RSA public key given as hex `modulus`/`exponent`
/// (the strings Steam returns), returning the base64 ciphertext Steam expects.
pub fn encrypt_password(modulus: &str, exponent: &str, password: &str) -> Result<String, String> {
    let n = BigUint::from_bytes_be(&hex::decode(modulus).map_err(|e| e.to_string())?);
    let e = BigUint::from_bytes_be(&hex::decode(exponent).map_err(|e| e.to_string())?);
    let key = RsaPublicKey::new(n, e).map_err(|e| e.to_string())?;
    let ct = key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(BASE64_STANDARD.encode(ct))
}

/// Assemble a Steam auth session ticket. Returns `(full_ticket, auth_ticket)`:
/// `full_ticket` is hex-encoded for `AuthenticateUserTicket`; `auth_ticket` (GC token +
/// 24-byte session header) is the part the `ClientAuthList` CRC covers and the part sent
/// as the ticket in that message. Layout is little-endian, per node-steam-user.
pub fn build_auth_ticket(
    gc_token: &[u8],
    public_ip: u32,
    timestamp_ms: u32,
    connection_count: u32,
    ownership_ticket: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut auth = Vec::with_capacity(4 + gc_token.len() + 4 + 24);
    auth.extend_from_slice(&(gc_token.len() as u32).to_le_bytes());
    auth.extend_from_slice(gc_token);
    auth.extend_from_slice(&24u32.to_le_bytes()); // session header length
    auth.extend_from_slice(&1u32.to_le_bytes()); // unknown
    auth.extend_from_slice(&2u32.to_le_bytes()); // unknown
    auth.extend_from_slice(&public_ip.to_le_bytes());
    auth.extend_from_slice(&0u32.to_le_bytes()); // filler
    auth.extend_from_slice(&timestamp_ms.to_le_bytes());
    auth.extend_from_slice(&connection_count.to_le_bytes());

    let mut full = auth.clone();
    full.extend_from_slice(&(ownership_ticket.len() as u32).to_le_bytes());
    full.extend_from_slice(ownership_ticket);
    (full, auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    #[test]
    fn encrypt_password_roundtrips_against_its_key() {
        // generate a throwaway key, feed its public half as hex, encrypt, then decrypt
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pub_key = priv_key.to_public_key();
        let n_hex = hex::encode(pub_key.n().to_bytes_be());
        let e_hex = hex::encode(pub_key.e().to_bytes_be());

        let b64 = encrypt_password(&n_hex, &e_hex, "hunter2").unwrap();
        let ct = BASE64_STANDARD.decode(b64).unwrap();
        let pt = priv_key.decrypt(Pkcs1v15Encrypt, &ct).unwrap();
        assert_eq!(pt, b"hunter2");
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(encrypt_password("zz", "010001", "x").is_err());
    }

    #[test]
    fn build_auth_ticket_has_expected_layout() {
        let gc = vec![0xAAu8; 20];
        let own = vec![0xBBu8; 184];
        let (full, auth) = build_auth_ticket(&gc, 0x01020304, 1234, 1, &own);
        // auth part = 4 + gc.len() + 4 + 24
        assert_eq!(auth.len(), 4 + 20 + 4 + 24);
        // full = auth + 4 (ownership len) + ownership
        assert_eq!(full.len(), auth.len() + 4 + 184);
        assert_eq!(u32::from_le_bytes(auth[0..4].try_into().unwrap()), 20); // gc len prefix
        assert_eq!(&full[..auth.len()], &auth[..]); // auth is a prefix of full
    }

    #[test]
    fn steamid_from_jwt_reads_sub() {
        // header.payload.sig where payload = {"iss":"steam","sub":"76561198000000001"}
        let payload = BASE64_URL_SAFE_NO_PAD.encode(br#"{"iss":"steam","sub":"76561198000000001"}"#);
        let jwt = format!("eyJ0eXAiOiJKV1QifQ.{payload}.sig");
        assert_eq!(steamid_from_jwt(&jwt), Some(76561198000000001));
        assert_eq!(steamid_from_jwt("not-a-jwt"), None);
    }
}
