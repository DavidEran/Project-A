package com.wakelocktester

import android.content.Context
import android.os.PowerManager
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.junit.MockitoJUnitRunner

@RunWith(MockitoJUnitRunner::class)
class WakeLockManagerTest {

    @Mock lateinit var context: Context
    @Mock lateinit var powerManager: PowerManager
    @Mock lateinit var wakeLock: PowerManager.WakeLock

    private lateinit var manager: WakeLockManager

    @Before
    fun setUp() {
        `when`(context.getSystemService(Context.POWER_SERVICE)).thenReturn(powerManager)
        `when`(powerManager.newWakeLock(anyInt(), anyString())).thenReturn(wakeLock)
        `when`(wakeLock.isHeld).thenReturn(true)

        manager = WakeLockManager(context)
    }

    // ------------------------------------------------------------------
    // acquire()
    // ------------------------------------------------------------------

    @Test
    fun `acquire returns true on first call for a tag`() {
        assertTrue(manager.acquire("tag1"))
    }

    @Test
    fun `acquire returns false when same tag is active`() {
        manager.acquire("tag1")
        assertFalse(manager.acquire("tag1"))
    }

    @Test
    fun `acquire indefinite calls wakeLock acquire without timeout`() {
        manager.acquire("tag1", null)
        verify(wakeLock).acquire()
        verify(wakeLock, never()).acquire(anyLong())
    }

    @Test
    fun `acquire with timeout calls wakeLock acquire with timeout`() {
        manager.acquire("tag1", 60_000L)
        verify(wakeLock).acquire(60_000L)
    }

    @Test
    fun `acquire creates a session`() {
        manager.acquire("tag1")
        assertEquals(1, manager.allSessions().size)
        assertTrue(manager.allSessions().first().isActive)
    }

    // ------------------------------------------------------------------
    // release()
    // ------------------------------------------------------------------

    @Test
    fun `release returns null when no active lock exists`() {
        assertNull(manager.release("nonexistent"))
    }

    @Test
    fun `release returns completed session`() {
        manager.acquire("tag1")
        val session = manager.release("tag1")
        assertNotNull(session)
        assertFalse(session!!.isActive)
    }

    @Test
    fun `release calls wakeLock release`() {
        manager.acquire("tag1")
        manager.release("tag1")
        verify(wakeLock).release()
    }

    @Test
    fun `release records duration`() {
        manager.acquire("tag1")
        Thread.sleep(50)
        val session = manager.release("tag1")
        assertTrue(session!!.durationMs >= 50)
    }

    // ------------------------------------------------------------------
    // releaseAll()
    // ------------------------------------------------------------------

    @Test
    fun `releaseAll releases multiple locks`() {
        val wl2: PowerManager.WakeLock = mock(PowerManager.WakeLock::class.java)
        `when`(wl2.isHeld).thenReturn(true)
        `when`(powerManager.newWakeLock(anyInt(), eq("tag2"))).thenReturn(wl2)

        manager.acquire("tag1")
        manager.acquire("tag2")
        val released = manager.releaseAll()
        assertEquals(2, released.size)
        assertFalse(manager.hasActiveLocks())
    }

    // ------------------------------------------------------------------
    // Status queries
    // ------------------------------------------------------------------

    @Test
    fun `isActive returns true after acquire`() {
        manager.acquire("tag1")
        assertTrue(manager.isActive("tag1"))
    }

    @Test
    fun `isActive returns false after release`() {
        manager.acquire("tag1")
        manager.release("tag1")
        assertFalse(manager.isActive("tag1"))
    }

    @Test
    fun `hasActiveLocks returns false initially`() {
        assertFalse(manager.hasActiveLocks())
    }

    @Test
    fun `hasActiveLocks returns true after acquire`() {
        manager.acquire("tag1")
        assertTrue(manager.hasActiveLocks())
    }

    // ------------------------------------------------------------------
    // Session queries
    // ------------------------------------------------------------------

    @Test
    fun `activeSessions returns only active sessions`() {
        manager.acquire("tag1")
        manager.acquire("tag2")
        manager.release("tag1")
        val active = manager.activeSessions()
        assertEquals(1, active.size)
        assertEquals("tag2", active.first().tag)
    }

    @Test
    fun `completedSessions returns only completed sessions`() {
        manager.acquire("tag1")
        manager.acquire("tag2")
        manager.release("tag1")
        val completed = manager.completedSessions()
        assertEquals(1, completed.size)
        assertEquals("tag1", completed.first().tag)
    }

    @Test
    fun `clearHistory removes only completed sessions`() {
        manager.acquire("tag1")
        manager.acquire("tag2")
        manager.release("tag1")
        manager.clearHistory()
        assertEquals(0, manager.completedSessions().size)
        assertEquals(1, manager.activeSessions().size)
    }

    // ------------------------------------------------------------------
    // Session.durationHuman
    // ------------------------------------------------------------------

    @Test
    fun `durationHuman milliseconds`() {
        val s = WakeLockManager.Session("t", System.currentTimeMillis() - 500, null)
        s.releaseTimeMs = System.currentTimeMillis()
        assertTrue(s.durationHuman.contains("ms"))
    }

    @Test
    fun `durationHuman seconds`() {
        val now = System.currentTimeMillis()
        val s = WakeLockManager.Session("t", now - 5_000, null)
        s.releaseTimeMs = now
        assertTrue(s.durationHuman.contains("s"))
    }

    @Test
    fun `durationHuman minutes`() {
        val now = System.currentTimeMillis()
        val s = WakeLockManager.Session("t", now - 120_000, null)
        s.releaseTimeMs = now
        assertTrue(s.durationHuman.contains("min"))
    }

    @Test
    fun `durationHuman hours`() {
        val now = System.currentTimeMillis()
        val s = WakeLockManager.Session("t", now - 7_200_000, null)
        s.releaseTimeMs = now
        assertTrue(s.durationHuman.contains("h"))
    }
}
