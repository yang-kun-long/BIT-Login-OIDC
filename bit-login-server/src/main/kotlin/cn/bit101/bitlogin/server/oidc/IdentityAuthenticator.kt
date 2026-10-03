package cn.bit101.bitlogin.server.oidc

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import cn.bit101.bitlogin.Config
import cn.bit101.bitlogin.http.HttpClient
import cn.bit101.bitlogin.login.SsoLogin
import cn.bit101.bitlogin.server.auth.ChallengeHandle
import cn.bit101.bitlogin.server.auth.ChallengeStore

interface IdentityAuthenticator {
    suspend fun start(username: String, password: String): ChallengeHandle
    suspend fun status(handle: ChallengeHandle): Map<String, Any?>
    suspend fun submitSms(handle: ChallengeHandle, code: String)
    suspend fun submitCaptcha(handle: ChallengeHandle, code: String)
    suspend fun authenticatedSubject(handle: ChallengeHandle): String?
}

class CasIdentityAuthenticator(
    private val challengeStore: ChallengeStore,
    private val connectTimeoutMs: Long = 5_000L,
    private val socketTimeoutMs: Long = 25_000L,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) : IdentityAuthenticator {
    override suspend fun start(username: String, password: String): ChallengeHandle {
        val account = username.trim()
        val handle = challengeStore.create(emptyList(), account)
        scope.launch {
            val session = HttpClient(connectTimeoutMs = connectTimeoutMs, socketTimeoutMs = socketTimeoutMs)
            try {
                val callbackUrl = Config.Urls.campus["jwb_cb"]
                    ?: throw IllegalStateException("BIT CAS callback is not configured")
                val login = SsoLogin(
                    session = session,
                    smsCodeCallback = { context -> challengeStore.waitForSms(handle.challengeId, context) },
                    captchaSolver = { image, context -> challengeStore.waitForCaptcha(handle.challengeId, image, context) },
                )
                val result = login.login(account, password, callbackUrl = callbackUrl)
                if (result.ticket.isNullOrBlank()) throw IllegalStateException("BIT CAS did not issue a service ticket")
                challengeStore.complete(handle.challengeId)
            } catch (e: Exception) {
                challengeStore.fail(handle.challengeId, e)
            } finally {
                session.close()
            }
        }
        return handle
    }

    override suspend fun status(handle: ChallengeHandle): Map<String, Any?> =
        challengeStore.snapshot(handle.challengeId, handle.accessToken)

    override suspend fun submitSms(handle: ChallengeHandle, code: String) {
        challengeStore.submitSms(handle.challengeId, handle.accessToken, code)
    }

    override suspend fun submitCaptcha(handle: ChallengeHandle, code: String) {
        challengeStore.submitCaptcha(handle.challengeId, handle.accessToken, code)
    }

    override suspend fun authenticatedSubject(handle: ChallengeHandle): String? {
        val state = challengeStore.authenticate(handle.challengeId, handle.accessToken)
        if (state["status"] != "authenticated") return null
        return (state["subject"] as? String)?.takeIf(String::isNotBlank)
    }
}
