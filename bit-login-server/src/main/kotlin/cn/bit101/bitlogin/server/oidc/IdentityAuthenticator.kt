package cn.bit101.bitlogin.server.oidc

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import cn.bit101.bitlogin.http.HttpClient
import cn.bit101.bitlogin.login.SsoLogin
import cn.bit101.bitlogin.server.auth.ChallengeHandle
import cn.bit101.bitlogin.server.auth.ChallengeStore

data class AuthenticatedIdentity(
    val subject: String,
    val name: String? = null,
)

interface IdentityAuthenticator {
    suspend fun start(username: String, password: String): ChallengeHandle
    suspend fun status(handle: ChallengeHandle): Map<String, Any?>
    suspend fun submitSms(handle: ChallengeHandle, code: String)
    suspend fun submitCaptcha(handle: ChallengeHandle, code: String)
    suspend fun authenticatedSubject(handle: ChallengeHandle): String?
    suspend fun authenticatedIdentity(handle: ChallengeHandle): AuthenticatedIdentity? =
        authenticatedSubject(handle)?.let { AuthenticatedIdentity(it) }
}

class CasIdentityAuthenticator(
    private val challengeStore: ChallengeStore,
    private val upstreamCallbackUrl: String = OidcConfig.DEFAULT_UPSTREAM_CALLBACK_URL,
    private val upstreamClientId: String = OidcConfig.DEFAULT_UPSTREAM_CLIENT_ID,
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
                val login = SsoLogin(
                    session = session,
                    smsCodeCallback = { context -> challengeStore.waitForSms(handle.challengeId, context) },
                    captchaSolver = { image, context -> challengeStore.waitForCaptcha(handle.challengeId, image, context) },
                )
                val result = login.login(
                    account,
                    password,
                    callbackUrl = upstreamCallbackUrl,
                    clientId = upstreamClientId,
                )
                val identity = result.user ?: login.getUser()
                if (identity.username != account) {
                    throw IllegalStateException("BIT CAS returned an unexpected authenticated account")
                }
                if (identity.name.isBlank()) {
                    throw IllegalStateException("BIT CAS did not return the authenticated user's name")
                }
                challengeStore.complete(handle.challengeId, identity.name)
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
        return authenticatedIdentity(handle)?.subject
    }

    override suspend fun authenticatedIdentity(handle: ChallengeHandle): AuthenticatedIdentity? {
        val state = challengeStore.authenticate(handle.challengeId, handle.accessToken)
        if (state["status"] != "authenticated") return null
        val subject = (state["subject"] as? String)?.takeIf(String::isNotBlank) ?: return null
        val name = (state["name"] as? String)?.trim()?.takeIf(String::isNotBlank)
        return AuthenticatedIdentity(subject, name)
    }
}
