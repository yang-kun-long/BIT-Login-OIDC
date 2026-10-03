package cn.bit101.bitlogin.server.oidc

import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import java.util.concurrent.ConcurrentHashMap
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import cn.bit101.bitlogin.server.auth.ChallengeHandle

class OidcAdminRoutesTest {
    @TempDir lateinit var tempDir: java.nio.file.Path

    private val config = OidcConfig(
        issuer = "http://127.0.0.1:16384",
        clientId = "test-client",
        redirectUris = setOf("http://127.0.0.1/callback"),
        signingKeyFile = "unused.pem",
        adminStudentIds = setOf("admin01"),
    )

    private class FakeAuthenticator : IdentityAuthenticator {
        private val accepted = ConcurrentHashMap<String, String>()
        override suspend fun start(username: String, password: String): ChallengeHandle {
            val id = "challenge-$username"
            if (password == "correct") accepted[id] = username
            return ChallengeHandle(id, "token-$username")
        }
        override suspend fun status(handle: ChallengeHandle): Map<String, Any?> =
            mapOf("status" to if (accepted.containsKey(handle.challengeId)) "authenticated" else "failed")
        override suspend fun submitSms(handle: ChallengeHandle, code: String) = Unit
        override suspend fun submitCaptcha(handle: ChallengeHandle, code: String) = Unit
        override suspend fun authenticatedSubject(handle: ChallengeHandle): String? = accepted[handle.challengeId]
    }

    @Test
    fun `CAS admin can manage blacklist while unauthenticated and csrf requests are rejected`() = testApplication {
        val admins = OidcAdminStore(config.adminStudentIds, config.adminSessionTtlSeconds)
        val blocklist = OidcBlocklistStore(tempDir.resolve("auth.db").toString())
        val grants = OidcGrantStore(config)
        application {
            routing {
                oidcAdminRoutes(config, admins, blocklist, grants, FakeAuthenticator())
            }
        }
        val browser = createClient { followRedirects = false }

        val loginPage = browser.get("/admin")
        assertEquals(HttpStatusCode.OK, loginPage.status)
        val html = loginPage.bodyAsText()
        val flow = Regex("name=\"flow_id\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val csrf = Regex("name=\"csrf\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val login = browser.submitForm(
            url = "/admin/login",
            formParameters = Parameters.build {
                append("flow_id", flow)
                append("csrf", csrf)
                append("username", "admin01")
                append("password", "correct")
            },
        )
        assertEquals(HttpStatusCode.Found, login.status)
        val authenticated = browser.get(login.headers[HttpHeaders.Location]!!)
        assertEquals(HttpStatusCode.Found, authenticated.status)
        val cookie = authenticated.headers[HttpHeaders.SetCookie]!!.substringBefore(';')
        assertTrue(authenticated.headers[HttpHeaders.SetCookie]!!.contains("HttpOnly"))
        assertTrue(authenticated.headers[HttpHeaders.SetCookie]!!.contains("SameSite=Strict"))

        val dashboard = browser.get("/admin") { header(HttpHeaders.Cookie, cookie) }
        assertEquals(HttpStatusCode.OK, dashboard.status)
        val dashboardHtml = dashboard.bodyAsText()
        assertTrue(dashboardHtml.contains("管理工作台"))
        assertTrue(dashboardHtml.contains("admin01"))
        val dashboardCsrf = Regex("name=\"csrf\" value=\"([^\"]+)\"").find(dashboardHtml)!!.groupValues[1]
        val otherToken = grants.issueAccessToken("other-id")
        val affectedToken = grants.issueAccessToken("test-student-01")

        val noCookie = browser.submitForm(
            url = "/admin/blocklist/add",
            formParameters = Parameters.build { append("student_id", "test-student-01") },
        )
        assertEquals(HttpStatusCode.Found, noCookie.status)
        assertFalse(blocklist.contains("test-student-01"))

        val badCsrf = browser.submitForm(
            url = "/admin/blocklist/add",
            formParameters = Parameters.build {
                append("csrf", "wrong")
                append("student_id", "test-student-01")
            },
        ) {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.Forbidden, badCsrf.status)
        assertFalse(blocklist.contains("test-student-01"))

        val add = browser.submitForm(
            url = "/admin/blocklist/add",
            formParameters = Parameters.build {
                append("csrf", dashboardCsrf)
                append("student_id", "test-student-01")
            },
        ) {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.Found, add.status)
        assertTrue(blocklist.contains("test-student-01"))
        assertEquals("other-id", grants.subjectForAccessToken(otherToken))
        assertNull(grants.subjectForAccessToken(affectedToken))
        assertTrue(add.headers[HttpHeaders.Location].orEmpty().contains("status=added"))

        val remove = browser.submitForm(
            url = "/admin/blocklist/remove",
            formParameters = Parameters.build {
                append("csrf", dashboardCsrf)
                append("student_id", "test-student-01")
            },
        ) {
            header(HttpHeaders.Cookie, cookie)
        }
        assertEquals(HttpStatusCode.Found, remove.status)
        assertFalse(blocklist.contains("test-student-01"))
    }

    @Test
    fun `CAS account outside the admin allowlist cannot access the workbench`() = testApplication {
        val admins = OidcAdminStore(config.adminStudentIds, config.adminSessionTtlSeconds)
        application {
            routing { oidcAdminRoutes(config, admins, OidcBlocklistStore(tempDir.resolve("auth.db").toString()), OidcGrantStore(config), FakeAuthenticator()) }
        }
        val browser = createClient { followRedirects = false }
        val loginPage = browser.get("/admin")
        val html = loginPage.bodyAsText()
        val flow = Regex("name=\"flow_id\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val csrf = Regex("name=\"csrf\" value=\"([^\"]+)\"").find(html)!!.groupValues[1]
        val login = browser.submitForm(
            url = "/admin/login",
            formParameters = Parameters.build {
                append("flow_id", flow)
                append("csrf", csrf)
                append("username", "student01")
                append("password", "correct")
            },
        )
        val denied = browser.get(login.headers[HttpHeaders.Location]!!)
        assertEquals(HttpStatusCode.Forbidden, denied.status)
        assertTrue(denied.bodyAsText().contains("没有管理工作台权限"))
    }
}
