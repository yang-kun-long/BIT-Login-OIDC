package cn.bit101.bitlogin.server.oidc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class OidcBlocklistStoreTest {
    @TempDir lateinit var tempDir: java.nio.file.Path

    @Test
    fun `blacklist is persisted and can be removed`() {
        val database = tempDir.resolve("auth.db").toString()
        val first = OidcBlocklistStore(database)

        assertTrue(first.add("test-student-01"))
        assertFalse(first.add("test-student-01"))
        assertTrue(first.contains("test-student-01"))
        assertEquals(listOf("test-student-01"), first.list().map { it.studentId })

        val afterRestart = OidcBlocklistStore(database)
        assertTrue(afterRestart.contains("test-student-01"))
        assertTrue(afterRestart.remove("test-student-01"))
        assertFalse(afterRestart.contains("test-student-01"))
        assertFalse(afterRestart.remove("test-student-01"))
    }

    @Test
    fun `invalid student identifiers are not persisted`() {
        val store = OidcBlocklistStore(tempDir.resolve("auth.db").toString())
        assertThrows(IllegalArgumentException::class.java) { store.add("invalid id") }
        assertTrue(store.list().isEmpty())
    }
}
