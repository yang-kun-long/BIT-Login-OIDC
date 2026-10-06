package cn.bit101.bitlogin.server.oidc

import java.net.URI
import java.nio.file.Paths
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class OidcApplication(
    val clientId: String,
    val name: String,
    val redirectUris: Set<String>,
    val accessTokenTtlSeconds: Int,
) {
    init {
        require(clientId.matches(Regex("[A-Za-z0-9._~-]{1,128}"))) { "OIDC application client ID is invalid" }
        require(name.isNotBlank() && name.length <= 128) { "OIDC application name is invalid" }
        require(redirectUris.isNotEmpty()) { "OIDC application must register at least one redirect URI" }
        require(accessTokenTtlSeconds in 60..2_592_000) {
            "OIDC application access token TTL must be between 60 and 2592000 seconds"
        }
        redirectUris.forEach { value ->
            val uri = URI(value)
            require(uri.isAbsolute && !uri.host.isNullOrBlank() && uri.rawFragment == null) {
                "OIDC redirect URIs must be absolute URLs without fragments"
            }
        }
    }
}

data class OidcConfig(
    val issuer: String,
    val clientId: String,
    val redirectUris: Set<String>,
    val signingKeyFile: String,
    val keyId: String = "oidc-1",
    val flowTtlSeconds: Int = 300,
    val codeTtlSeconds: Int = 60,
    val accessTokenTtlSeconds: Int = 604800,
    val adminStudentIds: Set<String> = emptySet(),
    val adminSessionTtlSeconds: Int = 1800,
    val adminCookieSecure: Boolean = false,
    val applications: Map<String, OidcApplication> = emptyMap(),
    /** Browser callback registered with the school's gateway for name lookup. */
    val upstreamCallbackUrl: String = DEFAULT_UPSTREAM_CALLBACK_URL,
    /** Public client ID registered for the school's gateway portal. */
    val upstreamClientId: String = DEFAULT_UPSTREAM_CLIENT_ID,
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
        require(accessTokenTtlSeconds in 60..2_592_000) { "OIDC_ACCESS_TOKEN_TTL must be between 60 and 2592000 seconds" }
        require(adminSessionTtlSeconds in 60..86400) { "OIDC_ADMIN_SESSION_TTL must be between 60 and 86400 seconds" }
        require(adminStudentIds.all(OidcBlocklistStore.STUDENT_ID::matches)) { "OIDC_ADMIN_STUDENT_IDS contains an invalid student ID" }
        redirectUris.forEach { value ->
            val uri = URI(value)
            require(uri.isAbsolute && !uri.host.isNullOrBlank() && uri.rawFragment == null) {
                "OIDC redirect URIs must be absolute URLs without fragments"
            }
        }
        require(applications.keys.all { it == applications[it]?.clientId }) { "OIDC application map keys must match client IDs" }
        val upstreamUri = URI(upstreamCallbackUrl)
        require(upstreamUri.isAbsolute && !upstreamUri.host.isNullOrBlank() && upstreamUri.rawFragment == null) {
            "BIT gateway callback URL must be an absolute URL without a fragment"
        }
        require(upstreamClientId.matches(Regex("[A-Za-z0-9._~-]{1,128}"))) {
            "BIT gateway client ID is invalid"
        }
    }

    fun registeredApplications(): List<OidcApplication> = when {
        applications.isNotEmpty() -> applications.values.toList()
        clientId.isBlank() || redirectUris.isEmpty() -> emptyList()
        else -> listOf(OidcApplication(clientId, clientId, redirectUris, accessTokenTtlSeconds))
    }.sortedBy { it.clientId }

    fun application(clientId: String): OidcApplication? = registeredApplications().firstOrNull { it.clientId == clientId }

    companion object {
        fun fromEnv(map: Map<String, String> = System.getenv()): OidcConfig {
            val dbPath = map["AUTH_DB_PATH"]?.ifBlank { "data/auth.db" } ?: "data/auth.db"
            val defaultKeyPath = Paths.get(dbPath).toAbsolutePath().resolveSibling("oidc-signing-key.pem").toString()
            val defaultTtl = (map["OIDC_ACCESS_TOKEN_TTL"] ?: "604800").toIntOrNull() ?: 604800
            val legacy = OidcConfig(
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
                accessTokenTtlSeconds = defaultTtl,
                adminStudentIds = map["OIDC_ADMIN_STUDENT_IDS"]
                    ?.split(',')
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    ?.toSet()
                    ?: emptySet(),
                adminSessionTtlSeconds = (map["OIDC_ADMIN_SESSION_TTL"] ?: "1800").toIntOrNull() ?: 1800,
                adminCookieSecure = map["OIDC_ADMIN_COOKIE_SECURE"]?.equals("true", ignoreCase = true) ?: false,
                upstreamCallbackUrl = map["OIDC_UPSTREAM_CALLBACK_URL"]?.trim()?.ifBlank { DEFAULT_UPSTREAM_CALLBACK_URL }
                    ?: map["BIT_GATEWAY_CALLBACK_URL"]?.trim()?.ifBlank { DEFAULT_UPSTREAM_CALLBACK_URL }
                    ?: DEFAULT_UPSTREAM_CALLBACK_URL,
                upstreamClientId = map["OIDC_UPSTREAM_CLIENT_ID"]?.trim()?.ifBlank { DEFAULT_UPSTREAM_CLIENT_ID }
                    ?: map["BIT_GATEWAY_CLIENT_ID"]?.trim()?.ifBlank { DEFAULT_UPSTREAM_CLIENT_ID }
                    ?: DEFAULT_UPSTREAM_CLIENT_ID,
            )
            val applications = parseApplications(map["OIDC_APPLICATIONS"])
            if (applications.isEmpty()) return legacy.copy(applications = parseTtlOverrides(legacy, map["OIDC_APP_TOKEN_TTLS"]))
            val first = applications.values.first()
            return legacy.copy(
                clientId = first.clientId,
                redirectUris = first.redirectUris,
                accessTokenTtlSeconds = first.accessTokenTtlSeconds,
                applications = applications,
            )
        }

        private fun parseApplications(raw: String?): Map<String, OidcApplication> {
            val value = raw?.trim().orEmpty()
            if (value.isBlank()) return emptyMap()
            val array = runCatching { Json.parseToJsonElement(value).jsonArray }.getOrElse {
                throw IllegalArgumentException("OIDC_APPLICATIONS must be a JSON array")
            }
            val parsed = array.associate { element ->
                val obj = element.jsonObject
                val clientId = obj["client_id"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("OIDC_APPLICATIONS entries require client_id")
                clientId to OidcApplication(
                    clientId = clientId,
                    name = obj["name"]?.jsonPrimitive?.content?.ifBlank { clientId } ?: clientId,
                    redirectUris = obj["redirect_uris"]?.jsonArray?.map { it.jsonPrimitive.content }?.toSet()
                        ?: throw IllegalArgumentException("OIDC_APPLICATIONS entries require redirect_uris"),
                    accessTokenTtlSeconds = obj["access_token_ttl_seconds"]?.jsonPrimitive?.content?.toIntOrNull() ?: 604800,
                )
            }
            require(parsed.size == array.size) { "OIDC_APPLICATIONS contains duplicate client IDs" }
            require(parsed.isNotEmpty()) { "OIDC_APPLICATIONS must be a non-empty JSON array" }
            return parsed
        }

        private fun parseTtlOverrides(config: OidcConfig, raw: String?): Map<String, OidcApplication> {
            val value = raw?.trim().orEmpty()
            if (value.isBlank()) return emptyMap()
            val base = OidcApplication(config.clientId, config.clientId, config.redirectUris, config.accessTokenTtlSeconds)
            val overrides = value.split(',').mapNotNull { item ->
                val parts = item.split('=', limit = 2).map(String::trim)
                if (parts.size != 2 || parts[0].isBlank()) null else parts[0] to (parts[1].toIntOrNull() ?: -1)
            }.toMap()
            require(overrides.keys.all { it == base.clientId }) {
                "OIDC_APP_TOKEN_TTLS can only override the registered OIDC_CLIENT_ID"
            }
            return mapOf(base.clientId to base.copy(accessTokenTtlSeconds = overrides[base.clientId] ?: base.accessTokenTtlSeconds))
        }

        /**
         * This is the registered BIT self-service portal route. It contains
         * only stable page identifiers; the authenticated name is read from
         * `/gate/getUser` after the browser-style callback completes.
         */
        const val DEFAULT_UPSTREAM_CALLBACK_URL =
            "https://sso.bit.edu.cn/gate/cas-success/personal-center-home-page?personId=667e67ca6b050d065ecbf781&pageId=666fffd2397df800012e5a4c&objectId=6889cb58bbce4700065c13b7"
        const val DEFAULT_UPSTREAM_CLIENT_ID = "OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w"
    }
}
