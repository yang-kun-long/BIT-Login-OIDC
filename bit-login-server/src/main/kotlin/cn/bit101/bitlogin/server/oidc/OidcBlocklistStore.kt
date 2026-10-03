package cn.bit101.bitlogin.server.oidc

import java.nio.file.Files
import java.nio.file.Paths
import java.sql.DriverManager

data class BlockedStudent(val studentId: String, val createdAt: Long)

class OidcBlocklistStore(database: String) {
    private val dbPath = Paths.get(database).toAbsolutePath().toString()

    init {
        Paths.get(dbPath).parent?.let(Files::createDirectories)
        connection().use { conn ->
            conn.createStatement().use { stmt ->
                stmt.execute("PRAGMA journal_mode=WAL")
                stmt.execute("PRAGMA busy_timeout=10000")
                stmt.execute(
                    """CREATE TABLE IF NOT EXISTS oidc_blocklist (
                        student_id TEXT PRIMARY KEY,
                        created_at INTEGER NOT NULL
                    )""".trimIndent(),
                )
            }
        }
    }

    fun list(): List<BlockedStudent> = connection().use { conn ->
        conn.prepareStatement("SELECT student_id, created_at FROM oidc_blocklist ORDER BY student_id").use { stmt ->
            stmt.executeQuery().use { rows ->
                buildList {
                    while (rows.next()) add(BlockedStudent(rows.getString("student_id"), rows.getLong("created_at")))
                }
            }
        }
    }

    fun contains(studentId: String): Boolean = connection().use { conn ->
        conn.prepareStatement("SELECT 1 FROM oidc_blocklist WHERE student_id = ? LIMIT 1").use { stmt ->
            stmt.setString(1, studentId)
            stmt.executeQuery().use { it.next() }
        }
    }

    fun add(studentId: String): Boolean {
        require(STUDENT_ID.matches(studentId)) { "Invalid student ID" }
        return connection().use { conn ->
            conn.prepareStatement("INSERT OR IGNORE INTO oidc_blocklist (student_id, created_at) VALUES (?, ?)").use { stmt ->
                stmt.setString(1, studentId)
                stmt.setLong(2, System.currentTimeMillis() / 1000L)
                stmt.executeUpdate() == 1
            }
        }
    }

    fun remove(studentId: String): Boolean = connection().use { conn ->
        conn.prepareStatement("DELETE FROM oidc_blocklist WHERE student_id = ?").use { stmt ->
            stmt.setString(1, studentId)
            stmt.executeUpdate() == 1
        }
    }

    private fun connection() = DriverManager.getConnection("jdbc:sqlite:$dbPath").also { conn ->
        conn.createStatement().use { it.execute("PRAGMA busy_timeout=10000") }
    }

    companion object {
        val STUDENT_ID = Regex("[A-Za-z0-9._-]{1,64}")
    }
}
