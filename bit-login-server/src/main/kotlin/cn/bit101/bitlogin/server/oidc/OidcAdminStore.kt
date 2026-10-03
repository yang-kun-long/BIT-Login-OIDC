package cn.bit101.bitlogin.server.oidc

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import cn.bit101.bitlogin.server.auth.ChallengeHandle

data class OidcAdminFlow(
    val id: String,
    val csrf: String,
    val expiresAt: Long,
    val challenge: ChallengeHandle? = null,
)

data class OidcAdminSession(
    val token: String,
    val csrf: String,
    val studentId: String,
    val expiresAt: Long,
)

class OidcAdminStore(
    private val allowedStudentIds: Set<String>,
    private val sessionTtlSeconds: Int,
) {
    private val lock = Any()
    private val random = SecureRandom()
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val flows = ConcurrentHashMap<String, OidcAdminFlow>()
    private val sessions = ConcurrentHashMap<String, OidcAdminSession>()

    fun createFlow(): OidcAdminFlow = synchronized(lock) {
        cleanup()
        OidcAdminFlow(randomToken(), randomToken(), now() + sessionTtlSeconds)
            .also { flows[it.id] = it }
    }

    fun getFlow(id: String): OidcAdminFlow? = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized null
        if (flow.expiresAt <= now()) {
            flows.remove(id)
            null
        } else flow
    }

    fun hasValidCsrf(flow: OidcAdminFlow, value: String): Boolean = secureEquals(flow.csrf, value)

    fun setChallenge(flowId: String, challenge: ChallengeHandle): Boolean = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized false
        if (flow.challenge != null) return@synchronized false
        flows[flowId] = flow.copy(challenge = challenge)
        true
    }

    fun resetChallenge(flowId: String): OidcAdminFlow? = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized null
        flows[flowId] = flow.copy(challenge = null)
        flows[flowId]
    }

    fun createSession(flowId: String, studentId: String): OidcAdminSession? = synchronized(lock) {
        val flow = getFlow(flowId) ?: return@synchronized null
        if (flow.challenge == null || studentId !in allowedStudentIds) return@synchronized null
        flows.remove(flowId)
        val token = randomToken()
        val session = OidcAdminSession(token, randomToken(), studentId, now() + sessionTtlSeconds)
        sessions[tokenHash(token)] = session.copy(token = "")
        session
    }

    fun getSession(token: String?): OidcAdminSession? = synchronized(lock) {
        if (token.isNullOrBlank()) return@synchronized null
        val hash = tokenHash(token)
        val session = sessions[hash] ?: return@synchronized null
        if (session.expiresAt <= now()) {
            sessions.remove(hash)
            null
        } else session
    }

    fun hasValidCsrf(session: OidcAdminSession, value: String): Boolean = secureEquals(session.csrf, value)

    fun revoke(token: String?) = synchronized(lock) {
        if (!token.isNullOrBlank()) sessions.remove(tokenHash(token))
    }

    fun cleanup() = synchronized(lock) {
        val timestamp = now()
        flows.entries.removeIf { it.value.expiresAt <= timestamp }
        sessions.entries.removeIf { it.value.expiresAt <= timestamp }
    }

    private fun randomToken(): String = ByteArray(32).also(random::nextBytes).let(encoder::encodeToString)
    private fun tokenHash(token: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.UTF_8)),
    )
    private fun secureEquals(expected: String, actual: String): Boolean = MessageDigest.isEqual(
        expected.toByteArray(Charsets.UTF_8), actual.toByteArray(Charsets.UTF_8),
    )
    private fun now(): Long = System.currentTimeMillis() / 1000L
}
