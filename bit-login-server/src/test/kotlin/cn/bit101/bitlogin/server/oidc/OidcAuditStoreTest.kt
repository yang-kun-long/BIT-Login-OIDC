package cn.bit101.bitlogin.server.oidc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class OidcAuditStoreTest {
    @TempDir lateinit var tempDir: java.nio.file.Path

    @Test
    fun `records newest first without secret fields`() {
        val store = OidcAuditStore(tempDir.resolve("auth.db").toString())

        store.record("admin01", "blacklist_add", "student01")
        store.record("admin01", "logout")

        assertEquals(2, store.count())
        val entries = store.list()
        assertEquals(2, entries.size)
        assertEquals("logout", entries[0].action)
        assertEquals("", entries[0].targetStudentId)
        assertEquals("blacklist_add", entries[1].action)
        assertEquals("student01", entries[1].targetStudentId)
        assertTrue(entries.all { it.actorStudentId == "admin01" })
    }

    @Test
    fun `list is bounded to requested size`() {
        val store = OidcAuditStore(tempDir.resolve("auth.db").toString())
        repeat(4) { store.record("admin01", "action-$it") }

        assertEquals(2, store.list(2).size)
        assertEquals(1, store.list(0).size)
    }
}
