# BIT Login OIDC Identity Gateway

For application developers, see the [Chinese integration guide](oidc-integration.md) for registration, configuration, the login sequence, account mapping, and acceptance checks. Applications are registered independently and may use separate token lifetimes.

This deployment mode verifies an account through BIT CAS and returns the authenticated login ID as `sub` and `student_id`, plus the name returned by the school's gateway as `name`. It does not return roles, grades, schedule, or other student profile data. The legacy API routes are not mounted in identity-only mode.

## OIDC Endpoints

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/oauth/authorize` |
| Token | `/oauth/token` |
| UserInfo | `/oauth/userinfo` |
| Signing keys | `/jwks` |
| Admin workbench | `/admin` |

The provider supports Authorization Code with `S256` PKCE, `state`, and `nonce`. It is a public client and does not accept a client secret. Request `openid student_id`; ID Token and UserInfo expose `sub`, `student_id`, and the authenticated `name`. Authorization codes are single-use and short-lived.

## Admin Workbench

The workbench is available only when `OIDC_ADMIN_STUDENT_IDS` contains one or more administrator IDs. An administrator signs in through the same BIT CAS identity flow; only an exact ID in this allowlist can manage the denylist. The allowlist is server configuration, not editable in the web UI.

Blocked IDs are stored in the same SQLite database configured by `AUTH_DB_PATH`. The table stores the ID and creation timestamp only. Blacklist checks happen after CAS login, during authorization-code redemption, and at UserInfo. Adding an ID also invalidates in-memory codes and access tokens for it. An ID Token already returned to a client cannot be recalled and remains cryptographically valid until its short expiry (at most 15 minutes with current configuration); clients should rely on short lifetimes and verify `exp`.

The workbench is also the operational handoff for school migration. It provides:

- **Overview:** listener availability, active login flows/tokens, blocked-account count, and audit count.
- **Application integration:** the registered client ID, exact redirect URI(s), issuer, and all OIDC endpoints.
- **Protocol and security:** Authorization Code, S256 PKCE, public-client authentication, scopes, returned claims, and signing-key metadata (`kid`, algorithm, and public key size only).
- **Access control:** the denylist and immediate revocation of that subject's in-memory grants.
- **Audit:** recent administrator login, logout, denylist, and denied-access actions. Audit rows contain only IDs, action names, targets, and timestamps.
- **Migration exports:** authenticated downloads at `/admin/export/oidc.json` and `/admin/export/oidc.md`. They contain public integration metadata suitable for an application request; they never contain private keys, passwords, tokens, or database paths.

Application registration and token lifetimes are deployment configuration and remain read-only from the browser. Changing the issuer, application callback allowlists, upstream authentication adapter, or TLS mode remains a reviewed deployment-config change followed by a restart; the workbench does not provide dynamic client registration or secret/key editing.

Use HTTPS for administration. On the HTTP campus pilot, cookies cannot be marked `Secure`; `SameSite=Strict`, `HttpOnly`, expiring server-side sessions, and CSRF tokens reduce browser-side risk but do not encrypt credentials or prevent same-network interception.

Admin sessions are held in memory and are cleared on service restart. The allowlist is read at startup, so changing administrator IDs requires a restart.

## Configuration

Set deployment-specific values outside source control:

```text
HOST=127.0.0.1
PORT=16384
IDENTITY_ONLY=true
AUTH_DB_PATH=/var/lib/bit-login/auth.db
OIDC_ISSUER=https://login.example.edu
OIDC_CLIENT_ID=example-app
OIDC_REDIRECT_URIS=https://app.example.edu/oidc/callback
OIDC_SIGNING_KEY_FILE=/var/lib/bit-login/oidc-signing-key.pem
OIDC_UPSTREAM_CALLBACK_URL=https://sso.bit.edu.cn/gate/cas-success/personal-center-home-page?personId=667e67ca6b050d065ecbf781&pageId=666fffd2397df800012e5a4c&objectId=6889cb58bbce4700065c13b7
OIDC_UPSTREAM_CLIENT_ID=OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w
OIDC_ADMIN_STUDENT_IDS=admin-id-1,admin-id-2
OIDC_ADMIN_SESSION_TTL=1800
OIDC_ADMIN_COOKIE_SECURE=true
```

`OIDC_REDIRECT_URIS` must exactly match each client callback. Keep production values, private keys, real addresses, and administrator IDs out of Git. For Windows, copy `deploy/windows/oidc-settings.example.ps1` to the ignored local file `deploy/windows/oidc-settings.ps1`, then set actual values there. Leave `AdminStudentIds` empty to keep the workbench disabled.

`OIDC_UPSTREAM_CALLBACK_URL` and `OIDC_UPSTREAM_CLIENT_ID` identify the registered school portal route used to read `/gate/getUser`. They are public routing metadata, not a password or client secret. Override them when the school changes the registered portal application; do not put one-time `ticket`, `code`, or `state` values in either setting.

## HTTPS Certificate

The Ktor service does not terminate TLS. `OIDC_SIGNING_KEY_FILE` is an RSA key used to sign ID Tokens; it is **not** an HTTPS/TLS certificate and must not be installed in a web server certificate store.

For production, terminate TLS at IIS/HTTP.sys or a maintained reverse proxy and forward traffic to the Ktor listener over loopback or a protected private interface. Prefer a campus DNS name and a certificate issued by a CA trusted by every browser and OIDC client. A private IP address is generally not eligible for a publicly trusted certificate; if the school requires a direct-IP URL, the campus PKI must issue a certificate with that IP in its Subject Alternative Name and client devices must trust the issuing CA. A self-signed certificate also requires explicit trust distribution and is not transparent secure HTTPS.

When TLS is in place:

1. Set `OIDC_ISSUER` to the exact `https://` origin clients use.
2. Register the exact callback URI with the client and allowlist it in `OIDC_REDIRECT_URIS`.
3. Set `OIDC_ADMIN_COOKIE_SECURE=true`.
4. Restrict certificate private-key read access to the TLS service account, monitor expiry, and renew before expiration.
5. Keep the backend port private; allow campus clients to reach only the TLS endpoint.

The RSA OIDC signing key is generated on first startup if absent. Persist it with restrictive filesystem permissions and back it up securely. Rotating it changes the JWKS public key; coordinate the new `kid` and client cache overlap. Never publish either private key.

## HTTP Campus Pilot

HTTP is suitable only for a tightly restricted, temporary campus test. It does not encrypt passwords, SMS codes, authorization codes, cookies, tokens, or responses. Network ACLs are additional containment, not a substitute for TLS. Do not use public/guest Wi-Fi, unmanaged devices, or production credentials. The OIDC issuer itself must be reachable from both the user's browser and the relying party's token-exchange process; a public OA server generally cannot reach a campus-only address without an approved private route or VPN.

For a Windows host, run with app-local Java 17, bind only the intended interface, and limit firewall ingress to school-approved campus ranges. Keep the SQLite database, generated signing key, and logs in an ACL-restricted data directory. Do not replace a host's existing Java installation.

## Verification

- Discovery and JWKS return `200` and contain no environment-specific addresses beyond the configured issuer.
- `/admin` is `404` when the admin allowlist is empty; otherwise a non-allowlisted account is denied.
- Authorized administrators can add/remove IDs; the list survives service restart.
- Blocked IDs cannot complete login, exchange an outstanding code, or use UserInfo.
- Legacy business endpoints return `404` in identity-only mode.
