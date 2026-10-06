# Source and Security Notes

## Source Provenance

This repository is based on the Kotlin project published at [BIT101-dev/BIT-Login](https://github.com/BIT101-dev/BIT-Login). Its README describes the project as a Kotlin port of [BIT101-dev/BIT-Login-Python](https://github.com/BIT101-dev/BIT-Login-Python) and links [BIT101-dev/BIT101-GO](https://github.com/BIT101-dev/BIT101-GO) as a reference implementation. The identity-only OIDC provider, admin workbench, deployment examples, and related documentation are additions for this deployment.

The upstream tree inspected for this release did not contain a `LICENSE`, `COPYING`, or `NOTICE` file. Source attribution does not itself grant a license. The maintainer must retain authorization from the relevant copyright holders before publishing or redistributing derivative source. No license has been added here to imply rights that were not granted.

Kotlin, Ktor, Nimbus JOSE + JWT, SQLite JDBC, and other dependencies remain subject to their respective upstream licenses. Consult the dependency metadata and each upstream license before redistributing packaged binaries.

## Identity Data

The OIDC identity-only mode returns the authenticated login account as `sub` and `student_id`, and returns the name supplied by the school's gateway as `name`. It does not request roles or other business profile data. The administrator allowlist and denylist use student/staff IDs; the denylist persists only ID and creation time. Applications must treat `name` as display data, never as an authorization key.

The admin workbench also stores a minimal audit trail of administrator actions: actor ID, action, target ID when applicable, and timestamp. It deliberately excludes passwords, verification codes, authorization codes, access tokens, database paths, and private-key material. Application/protocol exports are authenticated and contain only public OIDC integration metadata.

## Key and Certificate Separation

- The OIDC RSA signing private key signs ID Tokens. The provider publishes its corresponding public key via JWKS.
- An HTTPS/TLS certificate authenticates the network endpoint and encrypts browser/client connections. The Ktor service does not terminate TLS by itself.
- The two keys have different purposes, formats, rotation schedules, and storage locations. Never substitute one for the other or publish either private key.

See [OIDC pilot and certificate setup](oidc-pilot.md#https-certificate) for TLS termination and campus-CA requirements.
