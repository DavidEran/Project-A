package com.wakelocktester

import android.content.Context
import android.os.PowerManager
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages wake lock acquisition, tracking, and release.
 *
 * Keeps a record of every wake lock session so durations can be
 * reported after the lock is released.
 */
class WakeLockManager(private val context: Context) {

    companion object {
        private const val TAG = "WakeLockManager"
        const val DEFAULT_TAG = "WakeLockTester:DefaultLock"
    }

    data class Session(
        val tag: String,
        val acquireTimeMs: Long,
        val timeoutMs: Long?,          // null = indefinite
        var releaseTimeMs: Long? = null,
        var timedOut: Boolean = false,
    ) {
        val isActive: Boolean get() = releaseTimeMs == null

        /** Duration in ms. Returns elapsed time if still active. */
        val durationMs: Long
            get() = (releaseTimeMs ?: System.currentTimeMillis()) - acquireTimeMs

        val durationHuman: String get() = formatDuration(durationMs)

        private fun formatDuration(ms: Long): String = when {
            ms < 1_000       -> "${ms} ms"
            ms < 60_000      -> "%.1f s".format(ms / 1_000.0)
            ms < 3_600_000   -> "%.1f min".format(ms / 60_000.0)
            else             -> "%.2f h".format(ms / 3_600_000.0)
        }
    }

    private val powerManager: PowerManager =
        context.getSystemService(Context.POWER_SERVICE) as PowerManager

    /** Active wake lock instances keyed by tag. */
    private val activeLocks: ConcurrentHashMap<String, PowerManager.WakeLock> =
        ConcurrentHashMap()

    /** All sessions (active + completed), ordered by acquisition time. */
    private val sessions: MutableList<Session> = mutableListOf()

    /**
     * Acquire a partial wake lock with an optional timeout.
     *
     * @param tag      Wake lock tag (must be unique per active lock).
     * @param timeoutMs If > 0, the lock is automatically released after this many ms.
     *                  If null or 0, the lock is held indefinitely.
     * @return true if acquired successfully, false if a lock with this tag already exists.
     */
    fun acquire(tag: String = DEFAULT_TAG, timeoutMs: Long? = null): Boolean {
        if (activeLocks.containsKey(tag)) {
            Log.w(TAG, "Wake lock already active for tag: $tag")
            return false
        }

        val wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            tag
        ).also { it.setReferenceCounted(false) }

        val session = Session(
            tag = tag,
            acquireTimeMs = System.currentTimeMillis(),
            timeoutMs = timeoutMs,
        )

        if (timeoutMs != null && timeoutMs > 0) {
            wakeLock.acquire(timeoutMs)
            Log.i(TAG, "WakeLock acquired with timeout ${timeoutMs} ms — tag=$tag")
        } else {
            @Suppress("DEPRECATION")
            wakeLock.acquire()
            Log.i(TAG, "WakeLock acquired (indefinite) — tag=$tag")
        }

        activeLocks[tag] = wakeLock
        synchronized(sessions) { sessions.add(session) }
        return true
    }

    /**
     * Release the wake lock identified by [tag].
     *
     * @return The completed [Session], or null if no active lock was found.
     */
    fun release(tag: String = DEFAULT_TAG): Session? {
        val wakeLock = activeLocks.remove(tag) ?: run {
            Log.w(TAG, "No active wake lock found for tag: $tag")
            return null
        }

        if (wakeLock.isHeld) {
            wakeLock.release()
        }

        val session = synchronized(sessions) {
            sessions.lastOrNull { it.tag == tag && it.isActive }
        } ?: return null

        session.releaseTimeMs = System.currentTimeMillis()
        Log.i(TAG, "WakeLock released — tag=$tag, held=${session.durationHuman}")
        return session
    }

    /** Release all active wake locks. */
    fun releaseAll(): List<Session> {
        val tags = activeLocks.keys.toList()
        return tags.mapNotNull { release(it) }
    }

    /** @return true if a wake lock with [tag] is currently active. */
    fun isActive(tag: String = DEFAULT_TAG): Boolean = activeLocks.containsKey(tag)

    /** @return true if any wake lock is currently active. */
    fun hasActiveLocks(): Boolean = activeLocks.isNotEmpty()

    /** All sessions (active and completed). */
    fun allSessions(): List<Session> = synchronized(sessions) { sessions.toList() }

    /** Currently active sessions only. */
    fun activeSessions(): List<Session> =
        synchronized(sessions) { sessions.filter { it.isActive } }

    /** Completed (released) sessions only. */
    fun completedSessions(): List<Session> =
        synchronized(sessions) { sessions.filter { !it.isActive } }

    /** Clear the session history (does not release active locks). */
    fun clearHistory() = synchronized(sessions) {
        sessions.removeAll { !it.isActive }
    }
}
