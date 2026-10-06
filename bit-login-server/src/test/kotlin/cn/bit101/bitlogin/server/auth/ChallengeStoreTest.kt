package cn.bit101.bitlogin.server.auth

import java.nio.file.Files
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import cn.bit101.bitlogin.http.HttpClient
import cn.bit101.bitlogin.sso.CaptchaContext
import cn.bit101.bitlogin.sso.SmsCodeContext

class ChallengeStoreTest {
    @TempDir lateinit var tempDir: java.nio.file.Path
    private val openStores = mutableListOf<ChallengeStore>()

    private fun newStore(): ChallengeStore = ChallengeStore(
        database = tempDir.resolve("test.db").toString(),
        pendingTtl = 2,
        readyTtl = 10,
        pollIntervalMs = 50,
    ).also(openStores::add)

    @AfterEach
    fun closeStores() {
        openStores.forEach(ChallengeStore::close)
    }

    @Test
    fun `create returns handle and snapshot authenticates`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"), "user")
        assertEquals("running", store.snapshot(handle.challengeId, handle.accessToken)["status"])
        assertThrows(ChallengeError::class.java) {
            kotlinx.coroutines.runBlocking { store.snapshot(handle.challengeId, "wrong-token") }
        }
    }

    @Test
    fun `submit SMS code and waitForSms picks it up`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        val deferred = async { store.waitForSms(handle.challengeId, SmsCodeContext("", "138****8000")) }
        delay(200)
        store.submitSms(handle.challengeId, handle.accessToken, "123456")
        assertEquals("123456", deferred.await())
    }

    @Test
    fun `SMS code must be 4-8 digits`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        assertThrows(ChallengeError::class.java) {
            kotlinx.coroutines.runBlocking { store.submitSms(handle.challengeId, handle.accessToken, "abc") }
        }
        assertThrows(ChallengeError::class.java) {
            kotlinx.coroutines.runBlocking { store.submitSms(handle.challengeId, handle.accessToken, "123") }
        }
    }

    @Test
    fun `complete transitions to authenticated`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        store.complete(handle.challengeId, "测试用户")
        assertEquals("authenticated", store.snapshot(handle.challengeId, handle.accessToken)["status"])
        assertEquals("测试用户", store.authenticate(handle.challengeId, handle.accessToken)["name"])
    }

    @Test
    fun `delete removes challenge`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        store.delete(handle.challengeId, handle.accessToken)
        assertThrows(ChallengeError::class.java) {
            kotlinx.coroutines.runBlocking { store.snapshot(handle.challengeId, handle.accessToken) }
        }
    }

    @Test
    fun `store service session and restore`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        store.complete(handle.challengeId)
        val client = HttpClient()
        client.headers["X-Custom"] = "value"
        client.addCookie("test", "cookie", "sso.bit.edu.cn")
        val result = buildJsonObject { put("score", JsonPrimitive("A")) }
        store.storeService(handle.challengeId, "jwb", client, result)
        val restored = store.getSession(handle.challengeId, handle.accessToken, "jwb")
        assertEquals("value", restored.headers["X-Custom"])
        assertEquals("cookie", restored.cookieValue("test"))
        val storedResult = store.getResult(handle.challengeId, handle.accessToken, "jwb")
        assertEquals("A", storedResult["score"]?.jsonPrimitive?.content)
    }

    @Test
    fun `safe error redacts sensitive parameters`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        store.fail(handle.challengeId, RuntimeException("password=secret123 ticket=ST-abc"))
        val snap = store.snapshot(handle.challengeId, handle.accessToken)
        val error = snap["error"] as? String ?: ""
        assertFalse(error.contains("secret123"), "error should be redacted: $error")
        assertFalse(error.contains("ST-abc"), "error should be redacted: $error")
        assertTrue(error.contains("[redacted]"))
    }

    @Test
    fun `snapshot for waiting_sms includes masked phone`() = runBlocking {
        val store = newStore()
        val handle = store.create(listOf("jwb"))
        val job = launch { store.waitForSms(handle.challengeId, SmsCodeContext("", "138****8000", "password_second_factor")) }
        delay(200)
        val snap = store.snapshot(handle.challengeId, handle.accessToken)
        assertEquals("waiting_sms", snap["status"])
        assertEquals("138****8000", snap["masked_phone"])
        job.cancel()
    }

    @Test
    fun `captcha challenge exposes image and accepts one answer`() = runBlocking {
        val store = newStore()
        val handle = store.create(emptyList(), "student")
        val image = byteArrayOf(1, 2, 3, 4)
        val job = async {
            store.waitForCaptcha(handle.challengeId, image, CaptchaContext("password", username = "student"))
        }
        delay(200)
        val snapshot = store.snapshot(handle.challengeId, handle.accessToken)
        assertEquals("waiting_captcha", snapshot["status"])
        assertEquals(java.util.Base64.getEncoder().encodeToString(image), snapshot["captcha_image"])
        store.submitCaptcha(handle.challengeId, handle.accessToken, "aB12")
        assertEquals("aB12", job.await())
        assertThrows(ChallengeError::class.java) {
            kotlinx.coroutines.runBlocking { store.submitCaptcha(handle.challengeId, handle.accessToken, "aB12") }
        }
    }
}
