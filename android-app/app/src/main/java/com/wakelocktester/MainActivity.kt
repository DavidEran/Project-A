package com.wakelocktester

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

/**
 * Wake Lock Tester – main screen.
 *
 * Lets the user:
 *  • Acquire a PARTIAL_WAKE_LOCK with an optional timeout
 *  • Release the lock manually
 *  • See real-time duration while the lock is held
 *  • Review a session history table
 */
class MainActivity : AppCompatActivity() {

    private lateinit var manager: WakeLockManager

    // UI views
    private lateinit var tvPermissionStatus: TextView
    private lateinit var etTag: EditText
    private lateinit var etTimeout: EditText
    private lateinit var btnAcquire: Button
    private lateinit var btnRelease: Button
    private lateinit var btnReleaseAll: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvDuration: TextView
    private lateinit var tvHistory: TextView
    private lateinit var btnClearHistory: Button

    private val uiHandler = Handler(Looper.getMainLooper())
    private val tickRunnable = object : Runnable {
        override fun run() {
            refreshDuration()
            uiHandler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        manager = WakeLockManager(applicationContext)

        bindViews()
        showPermissionStatus()
        setupListeners()
        refreshUi()
    }

    override fun onResume() {
        super.onResume()
        uiHandler.post(tickRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(tickRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        manager.releaseAll()
    }

    // ------------------------------------------------------------------
    // Binding
    // ------------------------------------------------------------------

    private fun bindViews() {
        tvPermissionStatus = findViewById(R.id.tv_permission_status)
        etTag              = findViewById(R.id.et_tag)
        etTimeout          = findViewById(R.id.et_timeout)
        btnAcquire         = findViewById(R.id.btn_acquire)
        btnRelease         = findViewById(R.id.btn_release)
        btnReleaseAll      = findViewById(R.id.btn_release_all)
        tvStatus           = findViewById(R.id.tv_status)
        tvDuration         = findViewById(R.id.tv_duration)
        tvHistory          = findViewById(R.id.tv_history)
        btnClearHistory    = findViewById(R.id.btn_clear_history)
    }

    // ------------------------------------------------------------------
    // Permission check
    // ------------------------------------------------------------------

    private fun showPermissionStatus() {
        val pm = packageManager
        val permResult = pm.checkPermission(
            android.Manifest.permission.WAKE_LOCK,
            packageName
        )
        val granted = permResult == android.content.pm.PackageManager.PERMISSION_GRANTED
        tvPermissionStatus.text = if (granted) {
            "WAKE_LOCK permission: GRANTED"
        } else {
            "WAKE_LOCK permission: NOT GRANTED"
        }
        tvPermissionStatus.setTextColor(
            ContextCompat.getColor(
                this,
                if (granted) android.R.color.holo_green_dark
                else android.R.color.holo_red_dark
            )
        )
    }

    // ------------------------------------------------------------------
    // Listeners
    // ------------------------------------------------------------------

    private fun setupListeners() {
        btnAcquire.setOnClickListener { onAcquire() }
        btnRelease.setOnClickListener { onRelease() }
        btnReleaseAll.setOnClickListener { onReleaseAll() }
        btnClearHistory.setOnClickListener {
            manager.clearHistory()
            refreshHistory()
        }
    }

    private fun onAcquire() {
        val tag = etTag.text.toString().ifBlank { WakeLockManager.DEFAULT_TAG }
        val timeoutText = etTimeout.text.toString().trim()
        val timeoutMs = if (timeoutText.isBlank()) null else timeoutText.toLongOrNull()

        if (timeoutText.isNotBlank() && timeoutMs == null) {
            toast("Invalid timeout value")
            return
        }

        val success = manager.acquire(tag, timeoutMs)
        if (success) {
            val msg = if (timeoutMs != null) {
                "Acquired (timeout: ${timeoutMs} ms)"
            } else {
                "Acquired (indefinite)"
            }
            setStatus(msg, ok = true)
        } else {
            setStatus("Already active for tag: $tag", ok = false)
        }
        refreshUi()
    }

    private fun onRelease() {
        val tag = etTag.text.toString().ifBlank { WakeLockManager.DEFAULT_TAG }
        val session = manager.release(tag)
        if (session != null) {
            setStatus("Released — held for ${session.durationHuman}", ok = true)
        } else {
            setStatus("No active lock for tag: $tag", ok = false)
        }
        refreshUi()
    }

    private fun onReleaseAll() {
        val released = manager.releaseAll()
        setStatus("Released ${released.size} lock(s)", ok = true)
        refreshUi()
    }

    // ------------------------------------------------------------------
    // UI refresh
    // ------------------------------------------------------------------

    private fun refreshUi() {
        refreshButtons()
        refreshDuration()
        refreshHistory()
    }

    private fun refreshButtons() {
        val hasAny = manager.hasActiveLocks()
        btnRelease.isEnabled = hasAny
        btnReleaseAll.isEnabled = hasAny
    }

    private fun refreshDuration() {
        val active = manager.activeSessions()
        if (active.isEmpty()) {
            tvDuration.text = "No active wake lock"
            tvDuration.setTextColor(
                ContextCompat.getColor(this, android.R.color.darker_gray)
            )
        } else {
            val lines = active.joinToString("\n") { s ->
                "[${s.tag}]  ${s.durationHuman}" +
                        (s.timeoutMs?.let { "  (timeout: ${it} ms)" } ?: "  (indefinite)")
            }
            tvDuration.text = lines
            tvDuration.setTextColor(
                ContextCompat.getColor(this, android.R.color.holo_orange_dark)
            )
        }
        refreshButtons()
    }

    private fun refreshHistory() {
        val completed = manager.completedSessions()
        if (completed.isEmpty()) {
            tvHistory.text = "No completed sessions yet."
            return
        }
        val sb = StringBuilder()
        completed.reversed().forEachIndexed { idx, s ->
            sb.appendLine("#${idx + 1}  tag=${s.tag}")
            sb.appendLine("     held=${s.durationHuman}")
            s.timeoutMs?.let { sb.appendLine("     timeout=${it} ms") }
            sb.appendLine()
        }
        tvHistory.text = sb.toString().trimEnd()
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun setStatus(msg: String, ok: Boolean) {
        tvStatus.text = msg
        tvStatus.setTextColor(
            ContextCompat.getColor(
                this,
                if (ok) android.R.color.holo_green_dark else android.R.color.holo_red_dark
            )
        )
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
