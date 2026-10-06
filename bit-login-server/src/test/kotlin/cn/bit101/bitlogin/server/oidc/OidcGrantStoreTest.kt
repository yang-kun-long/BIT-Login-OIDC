package cn.bit101.bitlogin.server.oidc

import io.ktor.http.Url
import java.security.MessageDigest
import java.util.Base64
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import cn.bit101.bitlogin.server.auth.ChallengeHandle

class OidcGrantStoreTest {
    private val config = OidcConfig(
        issuer = "http://127.0.0.1:16384",
        clientId = "test-client",
        redirectUris = setOf("https://oa.example.test/auth/callback"),
        signingKeyFile = "unused.pem",
    )
    private val verifier = "a".repeat(43)

    private fun newFlow(store: OidcGrantStore): OidcLoginFlow {
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
        )
        return store.createFlow(
            OidcAuthorizationRequest(
                clientId = config.clientId,
                redirectUri = config.redirectUris.single(),
                state = "state-123",
                nonce = "nonce-456",
                codeChallenge = challenge,
                scope = "openid student_id",
            ),
        )
    }

    @Test
    fun `authorization code binds redirect nonce and PKCE then is one time`() {
        val store = OidcGrantStore(config)
        val flow = newFlow(store)
        assertTrue(store.setChallenge(flow.id, ChallengeHandle("challenge", "token")))
        val location = store.completeLogin(flow.id, "test-student-01", "测试用户")!!
        assertTrue(location.startsWith(config.redirectUris.single()))
        assertTrue(location.contains("state=state-123"))
        val code = Url(location).parameters["code"]!!

        assertNull(store.consumeAuthorizationCode(code, config.clientId, config.redirectUris.single(), "b".repeat(43)))
        val grant = store.consumeAuthorizationCode(code, config.clientId, config.redirectUris.single(), verifier)
        assertEquals("test-student-01", grant?.subject)
        assertEquals("nonce-456", grant?.nonce)
        assertEquals("测试用户", grant?.name)
        assertNull(store.consumeAuthorizationCode(code, config.clientId, config.redirectUris.single(), verifier))
    }

    @Test
    fun `authorization flow requires an authenticated challenge before issuing code`() {
        val store = OidcGrantStore(config)
        val flow = newFlow(store)
        assertNull(store.completeLogin(flow.id, "test-student-01"))
        assertFalse(store.hasValidCsrf(flow, "wrong"))
        assertTrue(store.hasValidCsrf(flow, flow.csrf))
    }

    @Test
    fun `revoking a subject invalidates outstanding codes and access tokens`() {
        val store = OidcGrantStore(config)
        val flow = newFlow(store)
        assertTrue(store.setChallenge(flow.id, ChallengeHandle("challenge", "token")))
        val codeLocation = store.completeLogin(flow.id, "test-student-01", "测试用户")!!
        val code = Url(codeLocation).parameters["code"]!!
        val token = store.issueAccessToken("test-student-01", name = "测试用户")

        store.revokeSubject("test-student-01")

        assertNull(store.consumeAuthorizationCode(code, config.clientId, config.redirectUris.single(), verifier))
        assertNull(store.subjectForAccessToken(token))
        assertNull(store.nameForAccessToken(token))
    }
}
