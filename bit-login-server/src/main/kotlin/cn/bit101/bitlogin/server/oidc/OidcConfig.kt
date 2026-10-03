package cn.bit101.bitlogin.server.oidc

import java.net.URI
import java.nio.file.Paths

data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val redirectUris: Set<String>,
    val signingKeyFile: String,
    val keyId: String = "oidc-1",
    val flowTtlSeconds: Int = 300,
    val codeTtlSeconds: Int = 60,
    val accessTokenTtlSeconds: Int = 300,
    val adminStudentIds: Set<String> = emptySet(),
    val adminSessionTtlSeconds: Int = 1800,
    val adminCookieSecure: Boolean = false,
) {
    init {
        val issuerUri = URI(issuer)
        require(issuerUri.scheme in setOf("http", "https") && !issuerUri.host.isNullOrBlank()) {
            "OIDC_ISSUER must be an absolute HTTP(S) URL"
        }
        require(issuerUri.rawQuery == null && issuerUri.rawFragment == null && issuerUri.rawPath.orEmpty().let { it.isEmpty() || it == "/" }) {
            "OIDC_ISSUER must not contain a path, query, or fragment"
        }
        require(flowTtlSeconds in 60..900) { "OIDC_FLOW_TTL must be between 60 and 900 seconds" }
        require(codeTtlSeconds in 10..300) { "OIDC_CODE_TTL must be between 10 and 300 seconds" }
        require(accessTokenTtlSeconds in 60..900) { "OIDC_ACCESS_TOKEN_TTL must be between 60 and 900 seconds" }
        require(adminSessionTtlSeconds in 60..86400) { "OIDC_ADMIN_SESSION_TTL must be between 60 and 86400 seconds" }
        require(adminStudentIds.all(OidcBlocklistStore.STUDENT_ID::matches)) { "OIDC_ADMIN_STUDENT_IDS contains an invalid student ID" }
        redirectUris.forEach { value ->
            val uri = URI(value)
            require(uri.isAbsolute && !uri.host.isNullOrBlank() && uri.rawFragment == null) {
                "OIDC redirect URIs must be absolute URLs without fragments"
            }
        }
    }

    companion object {
        fun fromEnv(map: Map<String, String> = System.getenv()): OidcConfig {
            val dbPath = map["AUTH_DB_PATH"]?.ifBlank { "data/auth.db" } ?: "data/auth.db"
            val defaultKeyPath = Paths.get(dbPath).toAbsolutePath().resolveSibling("oidc-signing-key.pem").toString()
            return OidcConfig(
                issuer = map["OIDC_ISSUER"]?.trim()?.trimEnd('/')?.ifBlank { "http://localhost:16384" }
                    ?: "http://localhost:16384",
                clientId = map["OIDC_CLIENT_ID"]?.trim().orEmpty(),
                redirectUris = map["OIDC_REDIRECT_URIS"]
                    ?.split(',')
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    ?.toSet()
                    ?: emptySet(),
                signingKeyFile = map["OIDC_SIGNING_KEY_FILE"]?.trim()?.ifBlank { defaultKeyPath } ?: defaultKeyPath,
                keyId = map["OIDC_KEY_ID"]?.trim()?.ifBlank { "oidc-1" } ?: "oidc-1",
                flowTtlSeconds = (map["OIDC_FLOW_TTL"] ?: "300").toIntOrNull() ?: 300,
                codeTtlSeconds = (map["OIDC_CODE_TTL"] ?: "60").toIntOrNull() ?: 60,
                accessTokenTtlSeconds = (map["OIDC_ACCESS_TOKEN_TTL"] ?: "300").toIntOrNull() ?: 300,
                adminStudentIds = map["OIDC_ADMIN_STUDENT_IDS"]
                    ?.split(',')
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    ?.toSet()
                    ?: emptySet(),
                adminSessionTtlSeconds = (map["OIDC_ADMIN_SESSION_TTL"] ?: "1800").toIntOrNull() ?: 1800,
                adminCookieSecure = map["OIDC_ADMIN_COOKIE_SECURE"]?.equals("true", ignoreCase = true) ?: false,
            )
        }
    }
}
