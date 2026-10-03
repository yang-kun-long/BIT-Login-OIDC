package cn.bit101.bitlogin.server.oidc

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.sql.Connection
import java.sql.DriverManager

data class OidcAuditEntry(
    val id: Long,
    val actorStudentId: String,
    val action: String,
    val targetStudentId: String,
    val createdAt: Long,
)

/** Stores a minimal, non-secret history of administrator actions. */
class OidcAuditStore(database: String) : AutoCloseable {
    private val lock = Any()
    private val dbPath: Path = Paths.get(database).toAbsolutePath()

    init {
        dbPath.parent?.let { Files.createDirectories(it) }
        connection().use { conn ->
            conn.createStatement().use { statement ->
                statement.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS oidc_admin_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        actor_student_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        target_student_id TEXT NOT NULL DEFAULT '',
                        created_at INTEGER NOT NULL
                    )
                    """.trimIndent(),
                )
                statement.executeUpdate(
                    "CREATE INDEX IF NOT EXISTS idx_oidc_admin_audit_created_at ON oidc_admin_audit(created_at DESC, id DESC)",
                )
            }
        }
    }

    fun record(actorStudentId: String, action: String, targetStudentId: String = "") = synchronized(lock) {
        require(actorStudentId.isNotBlank() && actorStudentId.length <= 128) { "Invalid audit actor" }
        require(action.isNotBlank() && action.length <= 128) { "Invalid audit action" }
        require(targetStudentId.length <= 128) { "Invalid audit target" }
        connection().use { conn ->
            conn.prepareStatement(
                "INSERT INTO oidc_admin_audit (actor_student_id, action, target_student_id, created_at) VALUES (?, ?, ?, ?)",
            ).use { statement ->
                statement.setString(1, actorStudentId)
                statement.setString(2, action)
                statement.setString(3, targetStudentId)
                statement.setLong(4, now())
                statement.executeUpdate()
            }
        }
    }

    fun list(limit: Int = 50): List<OidcAuditEntry> = synchronized(lock) {
        val boundedLimit = limit.coerceIn(1, 200)
        connection().use { conn ->
            conn.prepareStatement(
                "SELECT id, actor_student_id, action, target_student_id, created_at FROM oidc_admin_audit ORDER BY created_at DESC, id DESC LIMIT ?",
            ).use { statement ->
                statement.setInt(1, boundedLimit)
                statement.executeQuery().use { result ->
                    buildList {
                        while (result.next()) {
                            add(
                                OidcAuditEntry(
                                    id = result.getLong("id"),
                                    actorStudentId = result.getString("actor_student_id"),
                                    action = result.getString("action"),
                                    targetStudentId = result.getString("target_student_id"),
                                    createdAt = result.getLong("created_at"),
                                ),
                            )
                        }
                    }
                }
            }
        }
    }

    fun count(): Long = synchronized(lock) {
        connection().use { conn ->
            conn.createStatement().use { statement ->
                statement.executeQuery("SELECT COUNT(*) FROM oidc_admin_audit").use { result ->
                    if (result.next()) result.getLong(1) else 0L
                }
            }
        }
    }

    override fun close() = Unit

    private fun connection(): Connection = DriverManager.getConnection("jdbc:sqlite:${dbPath}").also { conn ->
        conn.createStatement().use { statement ->
            statement.execute("PRAGMA busy_timeout = 5000")
        }
    }

    private fun now(): Long = System.currentTimeMillis() / 1000L
}
