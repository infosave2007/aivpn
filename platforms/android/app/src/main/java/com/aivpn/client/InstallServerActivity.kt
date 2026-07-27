package com.aivpn.client

import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aivpn.client.databinding.ActivityInstallServerBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * SSH server-install wizard (C3): TOFU + install-server.sh over SSH, driven
 * through [AivpnJni]'s `sshInstall*` bridge (`aivpn-common::ssh_install` on
 * the Rust side, `ssh-install` feature — default-on in aivpn-android-core).
 *
 * Unlike [AdminActivity]/[PoolActivity], this does NOT talk to the active
 * tunnel session at all — it opens its own outbound SSH connection to
 * whatever host the user enters, entirely independent of VPN state. The
 * entry point is still gated to full Admin (role==2) from [MainActivity]'s
 * menu, matching the rest of the in-app admin section.
 *
 * Three steps, each a plain [LinearLayout] built in Kotlin and swapped into
 * `contentContainer` (same "build views in code, no per-dialog XML" style
 * as [AdminActivity.showAddDialog] / [MainActivity.showOptionsMenu]):
 *  1. TARGET   — host/port/user/auth/mode/server_ip/server_port/device-binding
 *  2. TOFU     — [AivpnJni.sshProbeHostkey] result, trust/cancel, "show script"
 *  3. INSTALL  — [AivpnJni.sshInstallStart]/[AivpnJni.sshInstallPoll] progress log
 *
 * **Device binding**: there is currently no JNI getter for this device's
 * mgmt-admin public key on Android (unlike the desktop CLI's
 * `--device-pubkey`), so `device_pubkey_b64` is always sent as `null` here —
 * the created admin client is NOT bound to this device. See the checkbox's
 * warning copy and the TODO on [buildParamsJson] below. Adding that getter
 * is separate work (would need a new JNI export + Rust-side key access), not
 * something to improvise here.
 */
class InstallServerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityInstallServerBinding

    private enum class Step { TARGET, TOFU, INSTALL }
    private var step = Step.TARGET

    // ── Step 1 form state (kept across back/forward navigation) ──
    private var host = ""
    private var port = "22"
    private var user = "root"
    private var authIsPassword = true
    private var password = ""
    private var keyPem = ""
    private var keyPassphrase = ""
    private var modeIsDocker = false
    private var serverIp = ""
    private var serverPort = ""
    private var deviceBinding = false

    // ── Step 2 (TOFU) state ──
    private sealed class TofuState {
        object Loading : TofuState()
        data class Success(val fingerprint: String) : TofuState()
        data class Error(val message: String) : TofuState()
    }
    private var tofuState: TofuState = TofuState.Loading
    private var confirmedFingerprint: String? = null

    // ── Step 3 (install) state ──
    private var installHandle: Long = -1L
    private var pollJob: Job? = null
    private val logLines = mutableListOf<String>()
    private var installFinished = false
    private var finishedExitCode: Int? = null
    private var finishedConnectionKey: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityInstallServerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { onBackStep() }
        renderStep()
    }

    override fun onDestroy() {
        super.onDestroy()
        pollJob?.cancel()
        // Best-effort: free the job's queued-events storage on the Rust side.
        // Does NOT cancel an in-flight install thread — see AivpnJni.sshInstallFree's
        // doc comment; only its output becomes unobservable after this.
        val h = installHandle
        if (h >= 1L && AivpnJni.isAvailable) {
            try { AivpnJni.sshInstallFree(h) } catch (_: Throwable) { }
        }
    }

    private fun onBackStep() {
        when (step) {
            Step.TARGET -> finish()
            Step.TOFU -> { step = Step.TARGET; renderStep() }
            Step.INSTALL -> {
                // Mid/post-install: leaving just stops observing (see onDestroy) —
                // matches AivpnJni.sshInstallFree's documented "no cancellation".
                finish()
            }
        }
    }

    private fun renderStep() {
        binding.contentContainer.removeAllViews()
        when (step) {
            Step.TARGET -> {
                binding.textStepTitle.text = getString(R.string.install_step1_title)
                binding.contentContainer.addView(buildTargetStep())
                binding.btnStepBack.text = getString(R.string.btn_cancel)
                binding.btnStepBack.visibility = View.VISIBLE
                binding.btnStepNext.text = getString(R.string.install_step_next)
                binding.btnStepNext.visibility = View.VISIBLE
                binding.btnStepNext.setOnClickListener { onTargetNext() }
            }
            Step.TOFU -> {
                binding.textStepTitle.text = getString(R.string.install_step2_title)
                binding.contentContainer.addView(buildTofuStep())
                binding.btnStepBack.text = getString(R.string.btn_cancel)
                binding.btnStepBack.visibility = View.VISIBLE
                val success = tofuState as? TofuState.Success
                binding.btnStepNext.text = getString(R.string.install_trust)
                binding.btnStepNext.visibility = if (success != null) View.VISIBLE else View.GONE
                binding.btnStepNext.setOnClickListener {
                    confirmedFingerprint = success?.fingerprint
                    step = Step.INSTALL
                    installFinished = false
                    finishedExitCode = null
                    finishedConnectionKey = null
                    logLines.clear()
                    renderStep()
                    startInstall()
                }
                if (tofuState is TofuState.Loading) probeHostkey()
            }
            Step.INSTALL -> {
                binding.textStepTitle.text = getString(R.string.install_step3_title)
                binding.contentContainer.addView(buildInstallStep())
                binding.btnStepBack.visibility = View.GONE
                binding.btnStepNext.visibility = View.GONE
            }
        }
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    // ──────────── Step 1: target ────────────

    private fun buildTargetStep(): View {
        val ctx = this
        val layout = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }

        fun label(res: Int) = TextView(ctx).apply {
            text = getString(res)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 12.dp, 0, 2.dp)
        }

        val hostInput = EditText(ctx).apply { hint = getString(R.string.install_hint_host); setText(host); setSingleLine(true) }
        val portInput = EditText(ctx).apply {
            hint = "22"; setText(port); setSingleLine(true)
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        val userInput = EditText(ctx).apply { hint = "root"; setText(user); setSingleLine(true) }

        layout.addView(label(R.string.install_hint_host)); layout.addView(hostInput)
        layout.addView(label(R.string.install_hint_port)); layout.addView(portInput)
        layout.addView(label(R.string.install_hint_user)); layout.addView(userInput)

        layout.addView(label(R.string.install_hint_auth))
        val authGroup = RadioGroup(ctx).apply { orientation = RadioGroup.HORIZONTAL }
        val rbPassword = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_auth_password) }
        val rbKeyPem = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_auth_key_pem) }
        authGroup.addView(rbPassword)
        authGroup.addView(rbKeyPem)
        authGroup.check(if (authIsPassword) rbPassword.id else rbKeyPem.id)
        layout.addView(authGroup)

        val passwordInput = EditText(ctx).apply {
            hint = getString(R.string.install_hint_password)
            setText(password)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            visibility = if (authIsPassword) View.VISIBLE else View.GONE
        }
        val keyPemInput = EditText(ctx).apply {
            hint = getString(R.string.install_hint_key_pem)
            setText(keyPem)
            minLines = 3
            maxLines = 6
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            visibility = if (authIsPassword) View.GONE else View.VISIBLE
        }
        val passphraseInput = EditText(ctx).apply {
            hint = getString(R.string.install_hint_key_passphrase)
            setText(keyPassphrase)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
            visibility = if (authIsPassword) View.GONE else View.VISIBLE
        }
        authGroup.setOnCheckedChangeListener { _, checkedId ->
            val isPassword = checkedId == rbPassword.id
            passwordInput.visibility = if (isPassword) View.VISIBLE else View.GONE
            keyPemInput.visibility = if (isPassword) View.GONE else View.VISIBLE
            passphraseInput.visibility = if (isPassword) View.GONE else View.VISIBLE
        }
        layout.addView(passwordInput)
        layout.addView(keyPemInput)
        layout.addView(passphraseInput)

        layout.addView(label(R.string.install_hint_mode))
        val modeGroup = RadioGroup(ctx).apply { orientation = RadioGroup.HORIZONTAL }
        val rbSystemd = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_mode_systemd) }
        val rbDocker = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_mode_docker) }
        modeGroup.addView(rbSystemd)
        modeGroup.addView(rbDocker)
        modeGroup.check(if (modeIsDocker) rbDocker.id else rbSystemd.id)
        layout.addView(modeGroup)

        val serverIpInput = EditText(ctx).apply { hint = getString(R.string.install_hint_server_ip); setText(serverIp); setSingleLine(true) }
        val serverPortInput = EditText(ctx).apply {
            hint = getString(R.string.install_hint_server_port); setText(serverPort); setSingleLine(true)
            inputType = InputType.TYPE_CLASS_NUMBER
        }
        layout.addView(label(R.string.install_hint_server_ip)); layout.addView(serverIpInput)
        layout.addView(label(R.string.install_hint_server_port)); layout.addView(serverPortInput)

        val bindingCheck = CheckBox(ctx).apply {
            text = getString(R.string.install_device_binding)
            isChecked = deviceBinding
            setPadding(0, 14.dp, 0, 0)
        }
        val bindingWarning = TextView(ctx).apply {
            text = getString(R.string.install_device_binding_warning)
            textSize = 11f
            setTextColor(getColor(R.color.accent_lemon))
            setPadding(0, 2.dp, 0, 0)
            visibility = if (deviceBinding) View.VISIBLE else View.GONE
        }
        bindingCheck.setOnCheckedChangeListener { _, checked ->
            deviceBinding = checked
            bindingWarning.visibility = if (checked) View.VISIBLE else View.GONE
        }
        layout.addView(bindingCheck)
        layout.addView(bindingWarning)

        // Stash the live views on the layout tag so onTargetNext() can read
        // final values without redeclaring every field.
        layout.tag = TargetViews(
            hostInput, portInput, userInput, rbPassword, passwordInput,
            keyPemInput, passphraseInput, rbDocker, serverIpInput, serverPortInput,
        )
        return layout
    }

    private data class TargetViews(
        val host: EditText, val port: EditText, val user: EditText,
        val rbPassword: RadioButton, val password: EditText,
        val keyPem: EditText, val passphrase: EditText,
        val rbDocker: RadioButton, val serverIp: EditText, val serverPort: EditText,
    )

    private fun onTargetNext() {
        val v = binding.contentContainer.getChildAt(0).tag as? TargetViews ?: return
        host = v.host.text.toString().trim()
        port = v.port.text.toString().trim().ifEmpty { "22" }
        user = v.user.text.toString().trim().ifEmpty { "root" }
        authIsPassword = v.rbPassword.isChecked
        password = v.password.text.toString()
        keyPem = v.keyPem.text.toString()
        keyPassphrase = v.passphrase.text.toString()
        modeIsDocker = v.rbDocker.isChecked
        serverIp = v.serverIp.text.toString().trim()
        serverPort = v.serverPort.text.toString().trim()

        if (host.isEmpty()) {
            Toast.makeText(this, getString(R.string.install_hint_host), Toast.LENGTH_SHORT).show()
            return
        }
        val portInt = port.toIntOrNull()
        if (portInt == null || portInt !in 1..65535) {
            Toast.makeText(this, getString(R.string.install_error_bad_port), Toast.LENGTH_SHORT).show()
            return
        }
        if (user.isEmpty()) {
            Toast.makeText(this, getString(R.string.install_hint_user), Toast.LENGTH_SHORT).show()
            return
        }
        if (authIsPassword && password.isEmpty()) {
            Toast.makeText(this, getString(R.string.install_error_need_password), Toast.LENGTH_SHORT).show()
            return
        }
        if (!authIsPassword && keyPem.isBlank()) {
            Toast.makeText(this, getString(R.string.install_error_need_key), Toast.LENGTH_SHORT).show()
            return
        }
        if (!AivpnJni.isAvailable) {
            Toast.makeText(this, getString(R.string.install_error_core_unavailable), Toast.LENGTH_LONG).show()
            return
        }

        step = Step.TOFU
        tofuState = TofuState.Loading
        renderStep()
    }

    // ──────────── Step 2: TOFU ────────────

    private fun buildTofuStep(): View {
        val ctx = this
        val layout = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL }

        when (val s = tofuState) {
            is TofuState.Loading -> {
                layout.addView(ProgressBar(ctx).apply { setPadding(0, 24.dp, 0, 8.dp) })
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_tofu_probing, host)
                    setTextColor(getColor(R.color.text_secondary))
                })
            }
            is TofuState.Error -> {
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_tofu_error, s.message)
                    setTextColor(getColor(R.color.disconnect))
                    setPadding(0, 16.dp, 0, 8.dp)
                })
                val retry = android.widget.Button(ctx).apply { text = getString(R.string.install_tofu_retry) }
                retry.setOnClickListener { tofuState = TofuState.Loading; renderStep() }
                layout.addView(retry)
            }
            is TofuState.Success -> {
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_tofu_fingerprint_label)
                    textSize = 12f
                    setTextColor(getColor(R.color.text_secondary))
                    setPadding(0, 16.dp, 0, 4.dp)
                })
                layout.addView(TextView(ctx).apply {
                    text = s.fingerprint
                    textSize = 16f
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                    setTextColor(getColor(R.color.text_primary))
                    setTextIsSelectable(true)
                    gravity = Gravity.CENTER_HORIZONTAL
                })
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_tofu_confirm_hint)
                    textSize = 12f
                    setTextColor(getColor(R.color.text_secondary))
                    gravity = Gravity.CENTER_HORIZONTAL
                    setPadding(0, 8.dp, 0, 16.dp)
                })
                val showScript = android.widget.Button(ctx).apply {
                    text = getString(R.string.install_show_script)
                }
                showScript.setOnClickListener { showScriptDialog() }
                layout.addView(showScript)
            }
        }
        return layout
    }

    private fun probeHostkey() {
        val portInt = port.toIntOrNull() ?: 22
        lifecycleScope.launch {
            val fp = withContext(Dispatchers.IO) {
                try {
                    if (!AivpnJni.isAvailable) null else AivpnJni.sshProbeHostkey(host, portInt, user)
                } catch (t: Throwable) {
                    android.util.Log.e("InstallServerActivity", "sshProbeHostkey failed", t)
                    null
                }
            }
            tofuState = if (fp != null) TofuState.Success(fp)
                        else TofuState.Error(getString(R.string.install_tofu_error_generic))
            if (step == Step.TOFU) renderStep()
        }
    }

    private fun showScriptDialog() {
        lifecycleScope.launch {
            val (script, sha) = withContext(Dispatchers.IO) {
                try {
                    if (!AivpnJni.isAvailable) "" to "" else
                        AivpnJni.sshInstallScript() to AivpnJni.sshInstallScriptSha256()
                } catch (t: Throwable) { "" to "" }
            }
            val dialogCtx = android.view.ContextThemeWrapper(this@InstallServerActivity, R.style.Theme_AIVPN_Dialog)
            val layout = LinearLayout(dialogCtx).apply { orientation = LinearLayout.VERTICAL; setPadding(24.dp, 16.dp, 24.dp, 0) }
            layout.addView(TextView(dialogCtx).apply {
                text = getString(R.string.install_script_sha256, sha)
                textSize = 12f
                setTextColor(getColor(R.color.text_secondary))
                setTextIsSelectable(true)
                setPadding(0, 0, 0, 8.dp)
            })
            val scrollView = ScrollView(dialogCtx).apply {
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 400.dp)
            }
            scrollView.addView(TextView(dialogCtx).apply {
                text = script
                textSize = 10f
                typeface = android.graphics.Typeface.MONOSPACE
                setTextColor(getColor(R.color.text_primary))
                setTextIsSelectable(true)
            })
            layout.addView(scrollView)
            AlertDialog.Builder(this@InstallServerActivity)
                .setTitle(getString(R.string.install_show_script))
                .setView(layout)
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
    }

    // ──────────── Step 3: install ────────────

    private fun buildInstallStep(): View {
        val ctx = this
        val layout = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }

        if (!installFinished) {
            val row = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            row.addView(ProgressBar(ctx).apply { layoutParams = LinearLayout.LayoutParams(24.dp, 24.dp) })
            row.addView(TextView(ctx).apply {
                text = getString(R.string.install_running)
                setTextColor(getColor(R.color.text_secondary))
                setPadding(12.dp, 0, 0, 0)
            })
            layout.addView(row)
        } else {
            val key = finishedConnectionKey
            val code = finishedExitCode ?: -1
            if (key != null) {
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_success)
                    setTextColor(getColor(R.color.accent))
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                    setPadding(0, 0, 0, 8.dp)
                })
                val importBtn = android.widget.Button(ctx).apply { text = getString(R.string.install_import_profile) }
                importBtn.setOnClickListener { importProfile(key) }
                layout.addView(importBtn)
            } else {
                layout.addView(TextView(ctx).apply {
                    text = getString(R.string.install_failed, code)
                    setTextColor(getColor(R.color.disconnect))
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                    setPadding(0, 0, 0, 8.dp)
                })
            }
            val closeBtn = android.widget.Button(ctx).apply { text = getString(R.string.btn_cancel) }
            closeBtn.setOnClickListener { finish() }
            layout.addView(closeBtn)
        }

        val logView = TextView(ctx).apply {
            text = logLines.joinToString("\n")
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(getColor(R.color.text_secondary))
            setTextIsSelectable(true)
            setPadding(0, 16.dp, 0, 0)
        }
        layout.addView(logView)
        return layout
    }

    private fun appendLog(line: String) {
        logLines.add(line)
        if (step == Step.INSTALL) {
            // Cheap re-render of just the log text rather than the whole step
            // (avoids losing scroll position on the progress row above it).
            val container = binding.contentContainer
            val childCount = container.childCount
            if (childCount > 0) {
                val root = container.getChildAt(0) as? LinearLayout
                val logView = root?.getChildAt(root.childCount - 1) as? TextView
                if (logView != null) {
                    logView.text = logLines.joinToString("\n")
                    return
                }
            }
            renderStep()
        }
    }

    private fun startInstall() {
        val fingerprint = confirmedFingerprint
        if (fingerprint == null || !AivpnJni.isAvailable) {
            appendLog(getString(R.string.install_error_core_unavailable))
            installFinished = true
            finishedExitCode = -1
            renderStep()
            return
        }
        val paramsJson = buildParamsJson(fingerprint)
        pollJob = lifecycleScope.launch {
            val handle = withContext(Dispatchers.IO) {
                try { AivpnJni.sshInstallStart(paramsJson) } catch (t: Throwable) {
                    android.util.Log.e("InstallServerActivity", "sshInstallStart failed", t); -1L
                }
            }
            installHandle = handle
            if (handle < 1L) {
                appendLog(getString(R.string.install_error_bad_params))
                installFinished = true
                finishedExitCode = -1
                renderStep()
                return@launch
            }
            while (true) {
                val ev = withContext(Dispatchers.IO) {
                    try { AivpnJni.sshInstallPoll(handle) } catch (t: Throwable) {
                        android.util.Log.e("InstallServerActivity", "sshInstallPoll failed", t); ""
                    }
                }
                when {
                    ev == null -> delay(300)
                    ev.isEmpty() -> break
                    else -> handleInstallEvent(ev)
                }
            }
            if (!installFinished) {
                // Job ended without ever emitting "finished" (shouldn't normally
                // happen — run_ssh_install_job always synthesizes one — but
                // guard so the UI never spins forever).
                installFinished = true
                finishedExitCode = -1
                renderStep()
            }
            withContext(Dispatchers.IO) {
                try { AivpnJni.sshInstallFree(handle) } catch (_: Throwable) { }
            }
        }
    }

    private fun handleInstallEvent(json: String) {
        val obj = try { JSONObject(json) } catch (_: Exception) { null } ?: return
        when (obj.optString("type")) {
            "connected" -> appendLog(getString(R.string.install_log_connected, obj.optString("fingerprint")))
            "uploading" -> appendLog(getString(R.string.install_log_uploading, obj.optString("what")))
            "line" -> appendLog(obj.optString("line"))
            "marker" -> {
                val stepName = obj.optString("step")
                val status = obj.optString("status")
                val code = if (obj.isNull("code")) null else obj.optString("code")
                val msg = if (obj.isNull("msg")) null else obj.optString("msg")
                appendLog("[$stepName/$status] " + markerText(code, msg))
                val key = if (obj.isNull("connection_key")) null else obj.optString("connection_key")
                if (!key.isNullOrBlank()) finishedConnectionKey = key
            }
            "finished" -> {
                installFinished = true
                finishedExitCode = obj.optInt("exit_code", -1)
                val key = if (obj.isNull("connection_key")) null else obj.optString("connection_key")
                if (!key.isNullOrBlank()) finishedConnectionKey = key
                appendLog(getString(R.string.install_log_finished, finishedExitCode))
                renderStep()
            }
        }
    }

    /**
     * Localizes known `##AIVPN` marker codes from deploy/install-server.sh.
     * Anything not in this table falls back to the marker's own `msg` (or the
     * bare code) as-is, per the task contract.
     */
    private fun markerText(code: String?, msg: String?): String {
        val resId = when (code) {
            "port_busy" -> R.string.install_marker_port_busy
            "no_masks" -> R.string.install_marker_no_masks
            "template_missing" -> R.string.install_marker_template_missing
            "unit_template_missing" -> R.string.install_marker_unit_template_missing
            "no_local_device_key" -> R.string.install_marker_no_local_device_key
            "root_required" -> R.string.install_marker_root_required
            "missing_server_ip" -> R.string.install_marker_missing_server_ip
            "add_client_failed" -> R.string.install_marker_add_client_failed
            "key_not_found" -> R.string.install_marker_key_not_found
            "unsupported_arch" -> R.string.install_marker_unsupported_arch
            "download_failed" -> R.string.install_marker_download_failed
            "checksum_mismatch" -> R.string.install_marker_checksum_mismatch
            "service_not_active" -> R.string.install_marker_service_not_active
            "port_not_listening" -> R.string.install_marker_port_not_listening
            "port_owned_by_other" -> R.string.install_marker_port_owned_by_other
            "docker_missing" -> R.string.install_marker_docker_missing
            "compose_missing" -> R.string.install_marker_compose_missing
            "container_not_running" -> R.string.install_marker_container_not_running
            else -> null
        }
        return if (resId != null) getString(resId) else (msg ?: code ?: "")
    }

    /**
     * Wire contract shared with `aivpn_common::ssh_install::install_params_from_json`
     * (see that function's doc comment / crates/aivpn-common/src/ssh_install.rs).
     *
     * TODO(device-binding): `device_pubkey_b64` is always `null` — Android has
     * no JNI export to read this device's mgmt-admin public key (unlike the
     * desktop CLI's `--device-pubkey`). Adding one is separate work: a new
     * `Java_com_aivpn_client_AivpnJni_get*` export plus whatever Rust-side
     * key store the mobile core would need to expose it from. Until then, an
     * admin client created via this wizard is never device-bound, regardless
     * of [deviceBinding] (surfaced to the user via
     * `install_device_binding_warning`).
     */
    private fun buildParamsJson(fingerprint: String): String {
        val root = JSONObject()
        root.put("host", host)
        root.put("port", port.toIntOrNull() ?: 22)
        root.put("user", user)

        val auth = JSONObject()
        if (authIsPassword) {
            auth.put("type", "password")
            auth.put("password", password)
        } else {
            auth.put("type", "key_pem")
            auth.put("pem", keyPem)
            if (keyPassphrase.isNotEmpty()) auth.put("passphrase", keyPassphrase)
        }
        root.put("auth", auth)

        root.put("fingerprint", fingerprint)
        root.put("binary", JSONObject().put("type", "default"))
        if (serverIp.isNotEmpty()) root.put("server_ip", serverIp)
        serverPort.toIntOrNull()?.let { root.put("server_port", it) }
        root.put("mode", if (modeIsDocker) "docker" else "systemd")
        root.put("device_pubkey_b64", JSONObject.NULL)
        root.put("extra_args", JSONArray())
        return root.toString()
    }

    private fun importProfile(connectionKey: String) {
        if (ConnectionKeyParser.parse(connectionKey) == null) {
            Toast.makeText(this, getString(R.string.error_profile_key_invalid), Toast.LENGTH_SHORT).show()
            return
        }
        val profiles = SecureStorage.loadProfiles(this).toMutableList()
        val profile = SecureStorage.ConnectionProfile(
            id = UUID.randomUUID().toString(),
            name = host.ifBlank { getString(R.string.install_title) },
            key = connectionKey,
        )
        profiles.add(profile)
        SecureStorage.saveProfiles(this, profiles)
        SecureStorage.saveActiveProfileId(this, profile.id)
        Toast.makeText(this, getString(R.string.install_profile_imported), Toast.LENGTH_SHORT).show()
        finish()
    }
}
