package cn.bit101.bitlogin.server.oidc

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import cn.bit101.bitlogin.server.auth.ChallengeHandle
import cn.bit101.bitlogin.server.auth.ChallengeStore
import cn.bit101.bitlogin.server.config.AppConfig
import cn.bit101.bitlogin.server.mainModule

class OidcRoutesTest {
    @TempDir lateinit var tempDir: java.nio.file.Path

    private val issuer = "http://127.0.0.1:16384"
    private val clientId = "test-reimbursement-oa"
    private val redirectUri = "https://oa.example.test/api/auth/oidc/callback"
    private val verifier = "a".repeat(43)

    private fun config(keyFile: String = tempDir.resolve("oidc-key.pem").toString()) = OidcConfig(
        issuer = issuer,
        clientId = clientId,
        redirectUris = setOf(redirectUri),
        signingKeyFile = keyFile,
    )

    private fun codeChallenge(): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
        java.security.MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
    )

    private fun authorizePath(uri: String = redirectUri, scope: String = "openid student_id"): String = URLBuilder("http://test.local/oauth/authorize").apply {
        parameters.append("response_type", "code")
        parameters.append("client_id", clientId)
        parameters.append("redirect_uri", uri)
        parameters.append("scope", scope)
        parameters.append("state", "state-abc")
        parameters.append("nonce", "nonce-abc")
        parameters.append("code_challenge", codeChallenge())
        parameters.append("code_challenge_method", "S256")
    }.buildString().removePrefix("http://test.local")

    private class FakeAuthenticator : IdentityAuthenticator {
        private val subjects = ConcurrentHashMap<String, String>()

        override suspend fun start(username: String, password: String): ChallengeHandle {
            val id = "challenge-${subjects.size}"
            if (password == "correct-password") subjects[id] = username
            return ChallengeHandle(id, "challenge-token-$id")
        }

        override suspend fun status(handle: ChallengeHandle): Map<String, Any?> =
            mapOf("status" to if (subjects.containsKey(handle.challengeId)) "authenticated" else "failed")

        override suspend fun submitSms(handle: ChallengeHandle, code: String) = Unit
        override suspend fun submitCaptcha(handle: ChallengeHandle, code: String) = Unit

        override suspend fun authenticatedSubject(handle: ChallengeHandle): String? = subjects[handle.challengeId]
    }

    @Test
    fun `authorization code flow returns only student id and validates signature and PKCE`() = testApplication {
        val oidcConfig = config()
        val signingKey = OidcSigningKey.loadOrCreate(oidcConfig.signingKeyFile, oidcConfig.keyId)
        val grants = OidcGrantStore(oidcConfig)
        val blocklist = OidcBlocklistStore(tempDir.resolve("userinfo-denylist.db").toString())
        application {
            install(ContentNegotiation) { json() }
            routing { oidcRoutes(oidcConfig, signingKey, grants, FakeAuthenticator(), blocklist) }
        }
        val browser = createClient { followRedirects = false }

        val loginPage = browser.get(authorizePath())
        assertEquals(HttpStatusCode.OK, loginPage.status)
        assertTrue(loginPage.headers[HttpHeaders.CacheControl].orEmpty().contains("no-store"))
        val html = loginPage.bodyAsText()
        val flowId = Regex("name=\"flow_id\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val csrf = Regex("name=\"csrf\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]

        val login = browser.submitForm(
            url = "/oauth/login",
            formParameters = Parameters.build {
                append("flow_id", flowId)
                append("csrf", csrf)
                append("username", "test-student-01")
                append("password", "correct-password")
            },
        )
        assertEquals(HttpStatusCode.Found, login.status)

        val pending = browser.get(login.headers[HttpHeaders.Location]!!)
        assertEquals(HttpStatusCode.Found, pending.status)
        val callback = Url(pending.headers[HttpHeaders.Location]!!)
        assertEquals("state-abc", callback.parameters["state"])
        val code = callback.parameters["code"]!!

        val tokenResponse = browser.submitForm(
            url = "/oauth/token",
            formParameters = Parameters.build {
                append("grant_type", "authorization_code")
                append("client_id", clientId)
                append("redirect_uri", redirectUri)
                append("code", code)
                append("code_verifier", verifier)
            },
        )
        assertEquals(HttpStatusCode.OK, tokenResponse.status)
        val tokenJson = Json.parseToJsonElement(tokenResponse.bodyAsText()).jsonObject
        val jwt = SignedJWT.parse(tokenJson["id_token"]!!.jsonPrimitive.content)
        val publicKey = JWKSet.parse(signingKey.jwks().toString()).keys.single() as RSAKey
        assertTrue(jwt.verify(RSASSAVerifier(publicKey.toRSAPublicKey())))
        assertEquals(issuer, jwt.jwtClaimsSet.issuer)
        assertEquals(clientId, jwt.jwtClaimsSet.audience.single())
        assertEquals("test-student-01", jwt.jwtClaimsSet.subject)
        assertEquals("test-student-01", jwt.jwtClaimsSet.getStringClaim("student_id"))
        assertEquals("nonce-abc", jwt.jwtClaimsSet.getStringClaim("nonce"))
        assertFalse(jwt.jwtClaimsSet.claims.containsKey("name"))

        val userinfo = browser.get("/oauth/userinfo") {
            header(HttpHeaders.Authorization, "Bearer ${tokenJson["access_token"]!!.jsonPrimitive.content}")
        }
        assertEquals(HttpStatusCode.OK, userinfo.status)
        val userinfoJson = Json.parseToJsonElement(userinfo.bodyAsText()).jsonObject
        assertEquals("test-student-01", userinfoJson["sub"]!!.jsonPrimitive.content)
        assertEquals("test-student-01", userinfoJson["student_id"]!!.jsonPrimitive.content)
        assertFalse(userinfoJson.containsKey("name"))

        blocklist.add("test-student-01")
        val blockedUserinfo = browser.get("/oauth/userinfo") {
            header(HttpHeaders.Authorization, "Bearer ${tokenJson["access_token"]!!.jsonPrimitive.content}")
        }
        assertEquals(HttpStatusCode.Unauthorized, blockedUserinfo.status)

        val replay = browser.submitForm(
            url = "/oauth/token",
            formParameters = Parameters.build {
                append("grant_type", "authorization_code")
                append("client_id", clientId)
                append("redirect_uri", redirectUri)
                append("code", code)
                append("code_verifier", verifier)
            },
        )
        assertEquals(HttpStatusCode.BadRequest, replay.status)
    }

    @Test
    fun `unregistered redirect is rejected without redirecting`() = testApplication {
        val oidcConfig = config()
        val signingKey = OidcSigningKey.loadOrCreate(oidcConfig.signingKeyFile, oidcConfig.keyId)
        application {
            install(ContentNegotiation) { json() }
            routing {
                oidcRoutes(
                    oidcConfig,
                    signingKey,
                    OidcGrantStore(oidcConfig),
                    FakeAuthenticator(),
                    OidcBlocklistStore(tempDir.resolve("redirect-denylist.db").toString()),
                )
            }
        }
        val response = client.get(authorizePath("https://attacker.example.test/callback"))
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertTrue(response.headers[HttpHeaders.Location].isNullOrBlank())
    }

    @Test
    fun `authorization requires the student id scope`() = testApplication {
        val oidcConfig = config()
        val signingKey = OidcSigningKey.loadOrCreate(oidcConfig.signingKeyFile, oidcConfig.keyId)
        application {
            install(ContentNegotiation) { json() }
            routing {
                oidcRoutes(
                    oidcConfig,
                    signingKey,
                    OidcGrantStore(oidcConfig),
                    FakeAuthenticator(),
                    OidcBlocklistStore(tempDir.resolve("scope-denylist.db").toString()),
                )
            }
        }
        val browser = createClient { followRedirects = false }
        val response = browser.get(authorizePath(scope = "openid"))
        assertEquals(HttpStatusCode.Found, response.status)
        assertTrue(response.headers[HttpHeaders.Location].orEmpty().contains("error=invalid_scope"))
    }

    @Test
    fun `blocked subject cannot redeem an outstanding authorization code`() = testApplication {
        val oidcConfig = config()
        val signingKey = OidcSigningKey.loadOrCreate(oidcConfig.signingKeyFile, oidcConfig.keyId)
        val grants = OidcGrantStore(oidcConfig)
        val blocklist = OidcBlocklistStore(tempDir.resolve("denylist.db").toString())
        application {
            install(ContentNegotiation) { json() }
            routing { oidcRoutes(oidcConfig, signingKey, grants, FakeAuthenticator(), blocklist) }
        }
        val browser = createClient { followRedirects = false }
        val page = browser.get(authorizePath())
        val html = page.bodyAsText()
        val flowId = Regex("name=\"flow_id\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val csrf = Regex("name=\"csrf\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        browser.submitForm(
            url = "/oauth/login",
            formParameters = Parameters.build {
                append("flow_id", flowId)
                append("csrf", csrf)
                append("username", "test-student-01")
                append("password", "correct-password")
            },
        )
        val pending = browser.get("/oauth/pending?flow_id=$flowId")
        val redirect = pending.headers[HttpHeaders.Location]!!
        val code = Url(redirect).parameters["code"]!!

        blocklist.add("test-student-01")
        val rejected = browser.submitForm(
            url = "/oauth/token",
            formParameters = Parameters.build {
                append("grant_type", "authorization_code")
                append("client_id", clientId)
                append("redirect_uri", redirectUri)
                append("code", code)
                append("code_verifier", verifier)
            },
        )
        assertEquals(HttpStatusCode.BadRequest, rejected.status)
        assertTrue(rejected.bodyAsText().contains("invalid_grant"))
    }

    @Test
    fun `identity only mode does not expose business routes`() = testApplication {
        val database = tempDir.resolve("identity-only.db").toString()
        val oidcConfig = config(tempDir.resolve("identity-only-key.pem").toString())
        lateinit var store: ChallengeStore
        application {
            store = mainModule(
                AppConfig.fromEnv().copy(authDbPath = database, identityOnly = true),
                oidcConfig,
            )
        }
        assertEquals(HttpStatusCode.OK, client.get("/").status)
        assertEquals(HttpStatusCode.OK, client.get("/.well-known/openid-configuration").status)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/jxzxehall/student_data").status)
        assertEquals(HttpStatusCode.NotFound, client.get("/api/jwb/score").status)
        assertEquals(HttpStatusCode.NotFound, client.get("/admin").status)
        store.close()
    }
}
