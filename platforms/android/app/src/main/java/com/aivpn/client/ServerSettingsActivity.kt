package com.aivpn.client

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aivpn.client.databinding.ActivityServerSettingsBinding
import kotlinx.coroutines.launch
import org.json.JSONArray

/**
 * Admin-only "Server Settings" screen (Wave 2 / G-A3): apply-with-rollback
 * for the two server-side "heavy" settings the tunnel's curated management
 * API exposes — the ACTIVE MASK override (live, no restart) and the GLOBAL
 * DEFAULT exit node (`pool.exit_node`, only takes effect after a server
 * restart). Both go through the exact same server "commit confirmed" flow
 * (`mgmt_service::apply_heavy`/`confirm_config`, `pending_config.rs`): the
 * server applies the change immediately and hands back a one-time token;
 * unless [AdminApi.confirmConfig] is called with that token within
 * `PENDING_CONFIG_TIMEOUT` (~120s), the server's OWN background sweep rolls
 * the change back on its own, with or without this screen still open —
 * [PendingSection]'s [CountDownTimer] is a local countdown for the UI, not
 * the authority: after it fires, the change is assumed reverted whether or
 * not this activity is even alive to see it.
 *
 * Reachable ONLY for Admin (role 2) — gated both by [AdminActivity] hiding
 * its entry button for Viewer/User, and defensively re-checked in
 * [onCreate] here (`finish()` immediately if the role check disagrees,
 * e.g. a stale deep link or a role downgrade mid-session).
 */
class ServerSettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivityServerSettingsBinding

    /** One `mask_id` per fetched option — see [fetchMaskOptions]. */
    private data class MaskOption(val id: String, val label: String, val generated: Boolean)

    private var maskOptions: List<MaskOption> = emptyList()

    /**
     * One row per client from `GET /api/v1/clients`, for the mask section's
     * client picker. The active-mask override is strictly PER-CLIENT on the
     * server (`.overrides/{client}.mask`; `resolve_heavy_setting`'s
     * `ActiveMask` arm 400s on an empty `client` — there is no server-wide
     * sentinel), so an apply without a selected client is never sent.
     */
    private data class ClientOption(val id: String, val name: String)

    private var clientOptions: List<ClientOption> = emptyList()

    private lateinit var maskSection: PendingSection
    private lateinit var exitSection: PendingSection

    /** True while an apply/confirm request for that section is in flight — belt-and-suspenders
     * against a double-tap racing two tokens/timers for the SAME section (the Apply button is
     * also disabled while a pending confirmation banner is showing, which is the main guard). */
    private var maskBusy = false
    private var exitBusy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val role = try {
            if (AivpnJni.isAvailable) AivpnJni.getRole() else -1
        } catch (_: Throwable) {
            -1
        }
        if (role != ROLE_ADMIN) {
            // Defense in depth — AdminActivity already hides the entry point for
            // non-Admin roles, so reaching here means a stale deep link/task or a
            // role downgrade that happened after the button was drawn.
            Toast.makeText(this, getString(R.string.admin_not_connected), Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        binding = ActivityServerSettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        maskSection = PendingSection(
            bannerRow = binding.rowMaskPending,
            bannerText = binding.textMaskBanner,
            confirmBtn = binding.btnConfirmMask,
            applyBtn = binding.btnApplyMask,
        )
        exitSection = PendingSection(
            bannerRow = binding.rowExitPending,
            bannerText = binding.textExitBanner,
            confirmBtn = binding.btnConfirmExit,
            applyBtn = binding.btnApplyExit,
        )

        binding.btnBack.setOnClickListener { finish() }
        binding.btnRefresh.setOnClickListener { loadOptions() }
        binding.btnApplyMask.setOnClickListener { onApplyMask() }
        binding.btnConfirmMask.setOnClickListener { onConfirmMask() }
        binding.btnApplyExit.setOnClickListener { onApplyExit() }
        binding.btnConfirmExit.setOnClickListener { onConfirmExit() }

        // Survive a configuration change (e.g. rotation) with a still-live pending
        // change: without this, losing `token`/the countdown from memory would
        // strand a change the server is still tracking — the admin would have no
        // way to confirm it from this screen short of re-applying (which
        // supersedes the still-pending entry rather than confirming it).
        savedInstanceState?.let { st ->
            st.getString(STATE_MASK_TOKEN)?.let { tok ->
                val remaining = st.getLong(STATE_MASK_REMAINING_MS, 0L)
                if (remaining > 0) maskSection.resume(tok, remaining)
            }
            st.getString(STATE_EXIT_TOKEN)?.let { tok ->
                val remaining = st.getLong(STATE_EXIT_REMAINING_MS, 0L)
                if (remaining > 0) exitSection.resume(tok, remaining)
            }
        }

        loadOptions()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        maskSection.token?.let {
            outState.putString(STATE_MASK_TOKEN, it)
            outState.putLong(STATE_MASK_REMAINING_MS, maskSection.remainingMs)
        }
        exitSection.token?.let {
            outState.putString(STATE_EXIT_TOKEN, it)
            outState.putLong(STATE_EXIT_REMAINING_MS, exitSection.remainingMs)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Only cancels the LOCAL countdown UI — the server-side rollback deadline
        // this mirrors is independent and keeps running whether or not this
        // activity (or its timers) are alive to observe it.
        //
        // The sections are assigned after the role guard above, and finish()
        // inside onCreate does NOT skip onDestroy — so on the guard's own path
        // (stale task restored with no live session, or a rotation after the
        // VPN dropped) these are still uninitialised and touching them threw
        // UninitializedPropertyAccessException, turning a graceful "not
        // connected" bounce into an app crash.
        if (::maskSection.isInitialized) maskSection.cancelTimer()
        if (::exitSection.isInitialized) exitSection.cancelTimer()
    }

    // ──────────── Mask options (spinner data source) ────────────

    private fun loadOptions() {
        lifecycleScope.launch {
            val statusResult = AdminApi.status()
            binding.textNotConnected.visibility = if (statusResult.notConnected) View.VISIBLE else View.GONE

            val clients = fetchClientOptions()
            clientOptions = clients
            if (clients.isEmpty()) {
                binding.spinnerMaskClient.visibility = View.GONE
                binding.textMaskClientEmpty.visibility = View.VISIBLE
            } else {
                binding.textMaskClientEmpty.visibility = View.GONE
                binding.spinnerMaskClient.visibility = View.VISIBLE
                binding.spinnerMaskClient.adapter = ArrayAdapter(
                    this@ServerSettingsActivity,
                    android.R.layout.simple_spinner_item,
                    clients.map { if (it.name.isNotBlank() && it.name != it.id) "${it.name} (${it.id})" else it.id }
                ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            }

            val options = fetchMaskOptions()
            maskOptions = options
            if (options.isEmpty()) {
                binding.spinnerMask.visibility = View.GONE
                binding.editMaskCustom.visibility = View.VISIBLE
                binding.textMaskEmpty.visibility = View.VISIBLE
            } else {
                binding.textMaskEmpty.visibility = View.GONE
                binding.editMaskCustom.visibility = View.GONE
                binding.spinnerMask.visibility = View.VISIBLE
                val labels = options.map {
                    if (it.generated) it.label + getString(R.string.mask_auto_marker) else it.label
                }
                binding.spinnerMask.adapter = ArrayAdapter(
                    this@ServerSettingsActivity, android.R.layout.simple_spinner_item, labels
                ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
            }
        }
    }

    /**
     * Client rows for the mask section's client picker, from
     * `GET /api/v1/clients` (same route [AdminActivity] lists). Returns an
     * empty list (never throws) on any failure — the caller then hides the
     * picker and [onApplyMask] refuses to send (an apply without a client is
     * guaranteed to 400 server-side, see [ClientOption]).
     */
    private suspend fun fetchClientOptions(): List<ClientOption> {
        val result = AdminApi.listClients()
        if (!result.ok) return emptyList()
        val arr = result.bodyArray() ?: return emptyList()
        val out = mutableListOf<ClientOption>()
        for (i in 0 until arr.length()) {
            val c = arr.optJSONObject(i) ?: continue
            val id = c.optString("id", c.optString("client_id", ""))
            if (id.isEmpty()) continue
            out.add(ClientOption(id = id, name = c.optString("name", "")))
        }
        return out
    }

    /**
     * Two sources, tried in order:
     *
     * 1. `GET /api/v1/masks` via [AdminApi.listMasks] — the documented contract
     *    (`id`/`file`/`size_bytes`/`modified`/`generated`). As of this wave this
     *    route is NOT in the tunnel's curated allowlist (verified against
     *    `mgmt_service.rs::classify_route`), so it currently always 404s — kept
     *    first so this screen starts working with zero Android changes the day
     *    that route is added server-side.
     * 2. [AivpnJni.getMaskCatalogJson] — the `MaskCatalog` control message the
     *    server already pushes to every connected session (`mask_id`/`label`/
     *    `generated`), the SAME source [MainActivity]'s connect-time mask picker
     *    reads. This is what actually populates the spinner today.
     *
     * Returns an empty list (never throws) if both sources are empty/unavailable
     * — the caller then falls back to a free-text mask-id field, same
     * graceful-degradation convention [AdminActivity.fetchExitNodeOptions] uses.
     */
    private suspend fun fetchMaskOptions(): List<MaskOption> {
        val restResult = AdminApi.listMasks()
        if (restResult.ok) {
            val arr = restResult.bodyArray()
            if (arr != null && arr.length() > 0) {
                val out = mutableListOf<MaskOption>()
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val id = o.optString("id", "")
                    if (id.isEmpty()) continue
                    out.add(MaskOption(id = id, label = id, generated = o.optBoolean("generated", false)))
                }
                if (out.isNotEmpty()) return out
            }
        }

        val catalogJson = try { AivpnJni.getMaskCatalogJson() } catch (_: Throwable) { "" }
        if (catalogJson.isNotEmpty()) {
            try {
                val arr = JSONArray(catalogJson)
                val out = mutableListOf<MaskOption>()
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val id = o.optString("mask_id", "")
                    if (id.isEmpty() || id == "auto") continue
                    out.add(MaskOption(id = id, label = o.optString("label", id), generated = o.optBoolean("generated", false)))
                }
                if (out.isNotEmpty()) return out
            } catch (_: Throwable) {
                // Malformed catalog JSON — fall through to the empty-list caller fallback.
            }
        }
        return emptyList()
    }

    // ──────────── Active mask apply/confirm ────────────

    private fun onApplyMask() {
        if (maskBusy) return
        val clientPos = binding.spinnerMaskClient.selectedItemPosition
        val clientId = if (clientPos in clientOptions.indices) clientOptions[clientPos].id else ""
        if (clientId.isEmpty()) {
            // Server-side hard requirement — an empty client 400s (per-client
            // override only), so fail fast with the same hint the picker shows.
            Toast.makeText(this, getString(R.string.server_settings_mask_no_clients), Toast.LENGTH_SHORT).show()
            return
        }
        val maskId = if (maskOptions.isNotEmpty()) {
            val pos = binding.spinnerMask.selectedItemPosition
            if (pos in maskOptions.indices) maskOptions[pos].id else ""
        } else {
            binding.editMaskCustom.text.toString().trim()
        }
        if (maskId.isEmpty()) {
            Toast.makeText(this, getString(R.string.server_settings_mask_id_hint), Toast.LENGTH_SHORT).show()
            return
        }
        maskBusy = true
        binding.btnApplyMask.isEnabled = false
        lifecycleScope.launch {
            val result = AdminApi.applyActiveMask(clientId, maskId)
            maskBusy = false
            binding.btnApplyMask.isEnabled = true
            handleApplyResult(result, maskSection)
        }
    }

    private fun onConfirmMask() {
        if (maskBusy) return
        val token = maskSection.token ?: return
        maskBusy = true
        binding.btnConfirmMask.isEnabled = false
        lifecycleScope.launch {
            val result = AdminApi.confirmConfig(token)
            maskBusy = false
            binding.btnConfirmMask.isEnabled = true
            handleConfirmResult(result, maskSection, token)
        }
    }

    // ──────────── Global default exit apply/confirm ────────────

    private fun onApplyExit() {
        if (exitBusy) return
        val addr = binding.editExitNode.text.toString().trim()
        exitBusy = true
        binding.btnApplyExit.isEnabled = false
        lifecycleScope.launch {
            // Empty field = explicit `null` — clears the global default entirely
            // (see AdminApi.applyGlobalExitNode's doc comment for the wire shape).
            val result = AdminApi.applyGlobalExitNode(addr.ifEmpty { null })
            exitBusy = false
            binding.btnApplyExit.isEnabled = true
            handleApplyResult(result, exitSection)
        }
    }

    private fun onConfirmExit() {
        if (exitBusy) return
        val token = exitSection.token ?: return
        exitBusy = true
        binding.btnConfirmExit.isEnabled = false
        lifecycleScope.launch {
            val result = AdminApi.confirmConfig(token)
            exitBusy = false
            binding.btnConfirmExit.isEnabled = true
            handleConfirmResult(result, exitSection, token)
        }
    }

    // ──────────── Shared apply/confirm result handling ────────────

    private fun handleApplyResult(result: MgmtResult, section: PendingSection) {
        when {
            result.notConnected -> Toast.makeText(this, getString(R.string.admin_not_connected), Toast.LENGTH_SHORT).show()
            result.ok -> {
                val token = result.bodyObject()?.optString("token", "") ?: ""
                if (token.isEmpty()) {
                    Toast.makeText(this, getString(R.string.admin_error_generic, result.status), Toast.LENGTH_SHORT).show()
                } else {
                    section.start(token)
                }
            }
            else -> Toast.makeText(this, describeError(result), Toast.LENGTH_LONG).show()
        }
    }

    private fun handleConfirmResult(result: MgmtResult, section: PendingSection, expectedToken: String) {
        // The section may already have moved on to a NEWER token (a fresh Apply
        // that fired while this Confirm was in flight, or the countdown already
        // hit zero and self-reverted) — only touch it if it still matches.
        if (section.token != expectedToken) return
        when {
            result.notConnected -> Toast.makeText(this, getString(R.string.admin_not_connected), Toast.LENGTH_SHORT).show()
            result.ok -> {
                section.confirmed()
                Toast.makeText(this, getString(R.string.server_settings_confirmed), Toast.LENGTH_SHORT).show()
            }
            else -> {
                // 404/409 here means the confirm window already closed and the
                // server auto-rolled back before this request even landed.
                section.revert(showToast = false)
                Toast.makeText(this, getString(R.string.server_settings_reverted), Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun describeError(result: MgmtResult): String {
        val reason = result.bodyObject()?.optString("reason")
            ?: result.bodyObject()?.optString("error")
        return if (!reason.isNullOrBlank()) {
            getString(R.string.admin_error_with_reason, result.status, reason)
        } else {
            getString(R.string.admin_error_generic, result.status)
        }
    }

    // ──────────── Shared pending-apply UI (apply → countdown → confirm) ────────────

    /**
     * One section's "apply-with-rollback" UI state — the SAME shape used for
     * both the mask and exit sections (see the class doc comment on why they
     * genuinely can be independent: the server tracks each `HeavySetting` as a
     * separate pending entry keyed by ITS OWN target file, so a pending mask
     * change and a pending exit-node change never collide with each other).
     *
     * Only one [token]/[CountDownTimer] is ever live per section at a time —
     * [applyBtn] is disabled for the whole time [bannerRow] is visible, so a
     * second Apply for the SAME section cannot fire while one is still pending
     * (avoiding a token/timer race against itself); [confirmBtn] is likewise
     * disabled for the duration of its own in-flight request via the
     * `maskBusy`/`exitBusy` flags in the outer class.
     */
    private inner class PendingSection(
        val bannerRow: LinearLayout,
        val bannerText: TextView,
        val confirmBtn: Button,
        val applyBtn: Button,
    ) {
        var token: String? = null
            private set

        /** Updated on every tick so [onSaveInstanceState] can restore an in-progress countdown. */
        var remainingMs: Long = 0L
            private set

        private var timer: android.os.CountDownTimer? = null

        /** Begin tracking a freshly-applied change: shows the banner and starts a fresh ~120s countdown. */
        fun start(newToken: String) {
            beginCountdown(newToken, PENDING_CONFIG_TIMEOUT_MS)
        }

        /** Restore an in-progress countdown after a configuration change (see [onSaveInstanceState]). */
        fun resume(existingToken: String, remaining: Long) {
            beginCountdown(existingToken, remaining)
        }

        private fun beginCountdown(newToken: String, durationMs: Long) {
            cancelTimer()
            token = newToken
            remainingMs = durationMs
            bannerRow.visibility = View.VISIBLE
            applyBtn.isEnabled = false
            confirmBtn.isEnabled = true
            renderBanner(durationMs)
            timer = object : android.os.CountDownTimer(durationMs, 1000L) {
                override fun onTick(millisUntilFinished: Long) {
                    remainingMs = millisUntilFinished
                    renderBanner(millisUntilFinished)
                }
                override fun onFinish() {
                    revert(showToast = true)
                }
            }.start()
        }

        private fun renderBanner(millisRemaining: Long) {
            val secs = ((millisRemaining + 999) / 1000).coerceAtLeast(0)
            bannerText.text = getString(R.string.server_settings_pending_banner, secs)
        }

        /** Confirmed — the change is now permanent; clear all pending state. */
        fun confirmed() {
            cancelTimer()
            token = null
            remainingMs = 0L
            bannerRow.visibility = View.GONE
            applyBtn.isEnabled = true
        }

        /** Timed out (or the server already reported it as gone) — clear pending state. */
        fun revert(showToast: Boolean) {
            cancelTimer()
            token = null
            remainingMs = 0L
            bannerRow.visibility = View.GONE
            applyBtn.isEnabled = true
            if (showToast) {
                Toast.makeText(this@ServerSettingsActivity, getString(R.string.server_settings_reverted), Toast.LENGTH_LONG).show()
            }
        }

        fun cancelTimer() {
            timer?.cancel()
            timer = null
        }
    }

    companion object {
        private const val ROLE_ADMIN = 2

        /** Mirrors the server's `pending_config::PENDING_CONFIG_TIMEOUT`. */
        private const val PENDING_CONFIG_TIMEOUT_MS = 120_000L

        private const val STATE_MASK_TOKEN = "mask_token"
        private const val STATE_MASK_REMAINING_MS = "mask_remaining_ms"
        private const val STATE_EXIT_TOKEN = "exit_token"
        private const val STATE_EXIT_REMAINING_MS = "exit_remaining_ms"
    }
}
