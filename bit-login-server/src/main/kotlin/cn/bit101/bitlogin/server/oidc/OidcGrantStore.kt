package cn.bit101.bitlogin.server.oidc

import io.ktor.http.URLBuilder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import cn.bit101.bitlogin.server.auth.ChallengeHandle

data class OidcAuthorizationRequest(
    val clientId: String,
    val redirectUri: String,
    val state: String,
    val nonce: String,
    val codeChallenge: String,
    val scope: String,
)

data class OidcLoginFlow(
    val id: String,
    val csrf: String,
    val request: OidcAuthorizationRequest,
    val expiresAt: Long,
    val challenge: ChallengeHandle? = null,
    val redirectLocation: String? = null,
)

data class OidcTokenGrant(val subject: String, val nonce: String)

data class OidcRuntimeStats(
    val activeLoginFlows: Int,
    val activeAuthorizationCodes: Int,
    val activeAccessTokens: Int,
)

class OidcGrantStore(private val config: OidcConfig) {
    private data class AuthorizationCode(
        val clientId: String,
        val redirectUri: String,
        val codeChallenge: String,
        val nonce: String,
        val subject: String,
        val expiresAt: Long,
    )

    private data class AccessToken(val subject: String, val expiresAt: Long)

    private val lock = Any()
    private val random = SecureRandom()
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val flows = ConcurrentHashMap<String, OidcLoginFlow>()
    private val authorizationCodes = ConcurrentHashMap<String, AuthorizationCode>()
    private val accessTokens = ConcurrentHashMap<String, AccessToken>()

    fun createFlow(request: OidcAuthorizationRequest): OidcLoginFlow = synchronized(lock) {
        cleanup()
        val id = randomToken(24)
        val flow = OidcLoginFlow(
            id = id,
            csrf = randomToken(24),
            request = request,
            expiresAt = nowSeconds() + config.flowTtlSeconds,
        )
        flows[id] = flow
        flow
    }

    fun getFlow(id: String): OidcLoginFlow? = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized null
        if (flow.expiresAt <= nowSeconds()) {
            flows.remove(id)
            null
        } else flow
    }

    fun hasValidCsrf(flow: OidcLoginFlow, value: String): Boolean = MessageDigest.isEqual(
        flow.csrf.toByteArray(Charsets.UTF_8),
        value.toByteArray(Charsets.UTF_8),
    )

    fun setChallenge(flowId: String, challenge: ChallengeHandle): Boolean = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized false
        if (flow.redirectLocation != null) return@synchronized false
        flows[flowId] = flow.copy(challenge = challenge)
        true
    }

    fun resetChallenge(flowId: String): OidcLoginFlow? = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized null
        flows[flowId] = flow.copy(challenge = null)
        flows[flowId]
    }

    fun completeLogin(flowId: String, subject: String): String? = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized null
        if (flow.challenge == null || subject.isBlank()) return@synchronized null
        flow.redirectLocation?.let { return@synchronized it }
        val code = randomToken(32)
        authorizationCodes[sha256(code)] = AuthorizationCode(
            clientId = flow.request.clientId,
            redirectUri = flow.request.redirectUri,
            codeChallenge = flow.request.codeChallenge,
            nonce = flow.request.nonce,
            subject = subject,
            expiresAt = nowSeconds() + config.codeTtlSeconds,
        )
        val redirect = URLBuilder(flow.request.redirectUri).apply {
            parameters.append("code", code)
            parameters.append("state", flow.request.state)
        }.buildString()
        flows[flowId] = flow.copy(redirectLocation = redirect)
        redirect
    }

    fun consumeAuthorizationCode(
        code: String,
        clientId: String,
        redirectUri: String,
        codeVerifier: String,
    ): OidcTokenGrant? = synchronized(lock) {
        if (!CODE_VERIFIER.matches(codeVerifier)) return@synchronized null
        val codeHash = sha256(code)
        val record = authorizationCodes[codeHash] ?: return@synchronized null
        if (record.expiresAt <= nowSeconds() ||
            record.clientId != clientId ||
            record.redirectUri != redirectUri ||
            !constantTimeEquals(record.codeChallenge, pkceChallenge(codeVerifier))
        ) return@synchronized null
        if (!authorizationCodes.remove(codeHash, record)) return@synchronized null
        OidcTokenGrant(record.subject, record.nonce)
    }

    fun issueAccessToken(subject: String): String = synchronized(lock) {
        val token = randomToken(32)
        accessTokens[sha256(token)] = AccessToken(subject, nowSeconds() + config.accessTokenTtlSeconds)
        token
    }

    fun subjectForAccessToken(token: String): String? = synchronized(lock) {
        val key = sha256(token)
        val record = accessTokens[key] ?: return@synchronized null
        if (record.expiresAt <= nowSeconds()) {
            accessTokens.remove(key)
            null
        } else record.subject
    }

    fun revokeSubject(subject: String) = synchronized(lock) {
        authorizationCodes.entries.removeIf { it.value.subject == subject }
        accessTokens.entries.removeIf { it.value.subject == subject }
    }

    fun runtimeStats(): OidcRuntimeStats = synchronized(lock) {
        cleanup()
        OidcRuntimeStats(
            activeLoginFlows = flows.size,
            activeAuthorizationCodes = authorizationCodes.size,
            activeAccessTokens = accessTokens.size,
        )
    }

    fun cleanup() = synchronized(lock) {
        val now = nowSeconds()
        flows.entries.removeIf { it.value.expiresAt <= now }
        authorizationCodes.entries.removeIf { it.value.expiresAt <= now }
        accessTokens.entries.removeIf { it.value.expiresAt <= now }
    }

    private fun randomToken(bytes: Int): String = ByteArray(bytes).also(random::nextBytes).let(encoder::encodeToString)

    private fun sha256(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)),
    )

    private fun constantTimeEquals(a: String, b: String): Boolean = MessageDigest.isEqual(
        a.toByteArray(Charsets.US_ASCII), b.toByteArray(Charsets.US_ASCII),
    )

    private fun pkceChallenge(verifier: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
    )

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000L

    companion object {
        private val CODE_VERIFIER = Regex("[A-Za-z0-9._~-]{43,128}")
    }
}
