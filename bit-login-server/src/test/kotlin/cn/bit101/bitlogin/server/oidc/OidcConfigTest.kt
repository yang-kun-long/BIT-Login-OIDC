package cn.bit101.bitlogin.server.oidc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OidcConfigTest {
    @Test
    fun `environment config parses admin allowlist and cookie settings`() {
        val config = OidcConfig.fromEnv(
            mapOf(
                "OIDC_ISSUER" to "https://login.example.edu/",
                "OIDC_CLIENT_ID" to "oa",
                "OIDC_REDIRECT_URIS" to "https://oa.example.edu/callback",
                "OIDC_ADMIN_STUDENT_IDS" to "admin01, admin02,,",
                "OIDC_ADMIN_SESSION_TTL" to "900",
                "OIDC_ADMIN_COOKIE_SECURE" to "true",
                "OIDC_UPSTREAM_CALLBACK_URL" to "https://sso.example.edu/gate/callback",
                "OIDC_UPSTREAM_CLIENT_ID" to "portal-client",
            ),
        )
        assertEquals("https://login.example.edu", config.issuer)
        assertEquals(setOf("admin01", "admin02"), config.adminStudentIds)
        assertEquals(900, config.adminSessionTtlSeconds)
        assertTrue(config.adminCookieSecure)
        assertEquals("https://sso.example.edu/gate/callback", config.upstreamCallbackUrl)
        assertEquals("portal-client", config.upstreamClientId)
    }

    @Test
    fun `admin workbench defaults off and to a local issuer`() {
        val config = OidcConfig.fromEnv(emptyMap())
        assertEquals("http://localhost:16384", config.issuer)
        assertTrue(config.adminStudentIds.isEmpty())
        assertFalse(config.adminCookieSecure)
        assertEquals(604800, config.accessTokenTtlSeconds)
    }

    @Test
    fun `applications can have independent token lifetimes`() {
        val config = OidcConfig.fromEnv(
            mapOf(
                "OIDC_ISSUER" to "https://login.example.edu",
                "OIDC_APPLICATIONS" to """[
                    {"client_id":"oa","name":"报销 OA","redirect_uris":["https://oa.example/callback"],"access_token_ttl_seconds":604800},
                    {"client_id":"library","name":"图书馆","redirect_uris":["https://library.example/callback"],"access_token_ttl_seconds":3600}
                ]""",
            ),
        )
        assertEquals(604800, config.application("oa")!!.accessTokenTtlSeconds)
        assertEquals(3600, config.application("library")!!.accessTokenTtlSeconds)
        assertEquals("https://library.example/callback", config.application("library")!!.redirectUris.single())
    }
}
