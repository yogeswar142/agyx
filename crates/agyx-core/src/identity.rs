//! OIDC `id_token` payload decoder — read-only identity extraction.
//!
//! # Security note
//! JWT **signatures are not verified**. The extracted `sub` and `email` are
//! account identifiers used solely for profile matching, display, and duplicate
//! detection.  They are **not** a security boundary.  Never rely on them for
//! authorization decisions.
//!
//! The decoded struct is intentionally never written to disk or to the OS
//! credential store.

use crate::AgyxError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use zeroize::Zeroize;

/// Extracted fields from an OIDC id_token payload.
///
/// **Not** a security boundary. See module-level note.
#[derive(Debug, Clone, Zeroize)]
pub struct AccountIdentity {
    /// The Google account subject identifier (stable, opaque user ID).
    pub sub: String,
    /// The Google account email address. May change; `sub` is the stable key.
    pub email: String,
    /// Display name (may be absent).
    pub name: Option<String>,
}

/// The JWT payload fields we care about.  Extra fields are silently ignored.
/// Intentionally does NOT implement `Serialize` — we never write this struct.
#[derive(Deserialize)]
struct IdTokenClaims {
    sub: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
}

/// Parse the raw AGY credential JSON blob (opaque bytes passed as a slice)
/// and extract the OIDC identity for identification only.
///
/// # Parameters
/// - `raw_blob` — the raw bytes read from the OS credential store.
///   They are **not** modified, normalized, or reserialised.  This function
///   operates on a read-only in-memory copy.
///
/// # Errors
/// Returns [`AgyxError::Internal`] if the blob is not valid JSON or lacks
/// the required OIDC fields (indicating an unexpected credential format).
pub fn extract_identity(raw_blob: &[u8]) -> Result<AccountIdentity, AgyxError> {
    // We operate on a read-only decoded view — never stored anywhere.
    let json: serde_json::Value =
        serde_json::from_slice(raw_blob).map_err(|e| AgyxError::Internal(format!(
            "AGY credential is not valid JSON: {e}"
        )))?;

    let id_token_str = json
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgyxError::Internal(
            "AGY credential does not contain an 'id_token' field. \
             Unexpected credential format.".into(),
        ))?;

    let claims = decode_id_token_payload(id_token_str)?;

    Ok(AccountIdentity {
        sub:   claims.sub,
        email: claims.email,
        name:  claims.name,
    })
}

/// Decode the payload section of a JWT without verifying the signature.
///
/// The payload is the second base64url-encoded segment of the JWT.
/// This function makes **no** cryptographic verification.
fn decode_id_token_payload(id_token: &str) -> Result<IdTokenClaims, AgyxError> {
    let parts: Vec<&str> = id_token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return Err(AgyxError::Internal(
            "id_token is not a valid JWT (expected at least 2 dot-separated segments)".into(),
        ));
    }

    let payload_b64 = parts[1];
    // base64url without padding — standard for JWTs.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| AgyxError::Internal(format!("id_token base64 decode error: {e}")))?;

    let claims: IdTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AgyxError::Internal(format!("id_token payload JSON parse error: {e}")))?;

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fake_jwt(sub: &str, email: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"fake"}"#);
        let payload_json = serde_json::json!({
            "iss": "https://accounts.google.com",
            "sub": sub,
            "email": email,
            "email_verified": true,
            "name": "Test User",
            "iat": 1_700_000_000u64,
            "exp": 1_700_003_600u64,
        });
        let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string());
        let sig = URL_SAFE_NO_PAD.encode(b"FAKE_SIGNATURE");
        format!("{header}.{payload}.{sig}")
    }

    fn make_fake_blob(sub: &str, email: &str) -> Vec<u8> {
        let jwt = make_fake_jwt(sub, email);
        serde_json::json!({
            "token": {
                "access_token": "REDACTED",
                "token_type": "Bearer",
                "refresh_token": "REDACTED",
                "expiry": "2024-01-01T00:00:00Z"
            },
            "auth_method": "consumer",
            "id_token": jwt
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn extracts_sub_and_email() {
        let blob = make_fake_blob("123456789", "user@example.com");
        let id = extract_identity(&blob).unwrap();
        assert_eq!(id.sub, "123456789");
        assert_eq!(id.email, "user@example.com");
        assert_eq!(id.name.as_deref(), Some("Test User"));
    }

    #[test]
    fn error_on_missing_id_token() {
        let blob = br#"{"token": {"access_token": "x"}}"#;
        assert!(extract_identity(blob).is_err());
    }

    #[test]
    fn error_on_invalid_json() {
        let blob = b"not json";
        assert!(extract_identity(blob).is_err());
    }
}
