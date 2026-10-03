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
            ),
        )
        assertEquals("https://login.example.edu", config.issuer)
        assertEquals(setOf("admin01", "admin02"), config.adminStudentIds)
        assertEquals(900, config.adminSessionTtlSeconds)
        assertTrue(config.adminCookieSecure)
    }

    @Test
    fun `admin workbench defaults off and to a local issuer`() {
        val config = OidcConfig.fromEnv(emptyMap())
        assertEquals("http://localhost:16384", config.issuer)
        assertTrue(config.adminStudentIds.isEmpty())
        assertFalse(config.adminCookieSecure)
    }
}
