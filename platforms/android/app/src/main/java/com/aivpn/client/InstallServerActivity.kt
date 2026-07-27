package com.aivpn.client

import android.net.Uri
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
import androidx.activity.result.contract.ActivityResultContracts
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
 * whatever host the user enters, entirely independent of VPN state. Unlike
 * [MainActivity]'s other in-app admin entries (which need role==1/2, i.e. an
 * already-connected, already-admin-enrolled profile), the options-menu entry
 * for this Activity is ALWAYS shown, including with zero saved profiles and
 * zero connections — provisioning your first server from scratch is the base
 * scenario, and nothing here exposes admin-only client-management
 * functionality (that stays behind [AdminActivity]/[MENU_ADMIN]).
 *
 * Three steps, each a plain [LinearLayout] built in Kotlin and swapped into
 * `contentContainer` (same "build views in code, no per-dialog XML" style
 * as [AdminActivity.showAddDialog] / [MainActivity.showOptionsMenu]):
 *  1. TARGET   — host/port/user/auth/mode/server_ip/server_port/device-binding
 *  2. TOFU     — [AivpnJni.sshProbeHostkey] result, trust/cancel, "show script"
 *  3. INSTALL  — [AivpnJni.sshInstallStart]/[AivpnJni.sshInstallPoll] progress log
 *
 * **Device binding**: when the checkbox is on, [devicePubkeyBase64] reads this
 * device's JIT-enrollment private key ([SecureStorage.loadDeviceKey] — the same
 * 32-byte X25519 scalar already passed as `staticPrivkey` into every
 * [AivpnJni.runTunnel] call, generating and persisting one first if this device
 * has never run a tunnel session yet), re-encodes it base64 STANDARD, and derives
 * the matching public key via [AivpnJni.devicePubkey]. That public key is sent as
 * `device_pubkey_b64` so the server creates a device-bound (admin-capable) client
 * at install time (mirrors the desktop CLI's `--device-pubkey`).
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

    // ── Step 1 binary-source state (G3: default / URL / local file via SAF) ──
    private enum class BinarySource { DEFAULT, URL, FILE }
    private var binarySource = BinarySource.DEFAULT
    private var binaryUrl = ""
    /** Absolute path of the copy in [cacheDir] after [pickBinaryFile] resolves — see
     *  [copyPickedBinaryToCache]'s doc comment for why a SAF `content://` Uri can't be
     *  passed to the Rust side directly. */
    private var binaryFilePath: String? = null
    private var binaryFileName: String = ""

    private val pickBinaryFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) onBinaryFilePicked(uri)
    }

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
        // Best-effort cleanup of the cached binary copy (see copyPickedBinaryToCache).
        // Only when installFinished: if a job is still running/uploading, run_ssh_install_job
        // owns the read of this path on its own background thread independent of this
        // Activity's lifecycle (same "no cancellation" caveat as sshInstallFree above) —
        // deleting it out from under an in-flight upload would corrupt that upload.
        if (installFinished) {
            binaryFilePath?.let { path ->
                try { java.io.File(path).delete() } catch (_: Throwable) { }
            }
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

        layout.addView(label(R.string.install_hint_binary_source))
        val binaryGroup = RadioGroup(ctx).apply { orientation = RadioGroup.HORIZONTAL }
        val rbBinaryDefault = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_binary_default) }
        val rbBinaryUrl = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_binary_url) }
        val rbBinaryFile = RadioButton(ctx).apply { id = View.generateViewId(); text = getString(R.string.install_binary_file) }
        binaryGroup.addView(rbBinaryDefault)
        binaryGroup.addView(rbBinaryUrl)
        binaryGroup.addView(rbBinaryFile)
        binaryGroup.check(
            when (binarySource) {
                BinarySource.DEFAULT -> rbBinaryDefault.id
                BinarySource.URL -> rbBinaryUrl.id
                BinarySource.FILE -> rbBinaryFile.id
            }
        )
        layout.addView(binaryGroup)

        val binaryUrlInput = EditText(ctx).apply {
            hint = getString(R.string.install_hint_binary_url)
            setText(binaryUrl)
            setSingleLine(true)
            visibility = if (binarySource == BinarySource.URL) View.VISIBLE else View.GONE
        }
        val binaryFileRow = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            visibility = if (binarySource == BinarySource.FILE) View.VISIBLE else View.GONE
        }
        val binaryFileLabel = TextView(ctx).apply {
            text = binaryFileName.ifEmpty { getString(R.string.install_no_file_selected) }
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(12.dp, 0, 0, 0)
        }
        val pickFileBtn = android.widget.Button(ctx).apply { text = getString(R.string.install_pick_binary_file) }
        pickFileBtn.setOnClickListener {
            // Sync whatever the user has typed so far before backgrounding into the
            // system file picker — onBinaryFilePicked() re-renders this step on return,
            // which would otherwise silently drop unsaved field edits (see
            // syncTargetFieldsFromViews()'s doc comment).
            syncTargetFieldsFromViews()
            pickBinaryFile.launch("*/*")
        }
        binaryFileRow.addView(pickFileBtn)
        binaryFileRow.addView(binaryFileLabel)
        binaryGroup.setOnCheckedChangeListener { _, checkedId ->
            binarySource = when (checkedId) {
                rbBinaryUrl.id -> BinarySource.URL
                rbBinaryFile.id -> BinarySource.FILE
                else -> BinarySource.DEFAULT
            }
            binaryUrlInput.visibility = if (binarySource == BinarySource.URL) View.VISIBLE else View.GONE
            binaryFileRow.visibility = if (binarySource == BinarySource.FILE) View.VISIBLE else View.GONE
        }
        layout.addView(binaryUrlInput)
        layout.addView(binaryFileRow)

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
        val bindingHint = TextView(ctx).apply {
            text = getString(R.string.install_device_binding_hint)
            textSize = 11f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 2.dp, 0, 0)
            visibility = if (deviceBinding) View.VISIBLE else View.GONE
        }
        bindingCheck.setOnCheckedChangeListener { _, checked ->
            deviceBinding = checked
            bindingHint.visibility = if (checked) View.VISIBLE else View.GONE
        }
        layout.addView(bindingCheck)
        layout.addView(bindingHint)

        // Stash the live views on the layout tag so onTargetNext() /
        // syncTargetFieldsFromViews() can read final values without redeclaring
        // every field.
        layout.tag = TargetViews(
            hostInput, portInput, userInput, rbPassword, passwordInput,
            keyPemInput, passphraseInput, rbDocker, serverIpInput, serverPortInput,
            binaryUrlInput,
        )
        return layout
    }

    private data class TargetViews(
        val host: EditText, val port: EditText, val user: EditText,
        val rbPassword: RadioButton, val password: EditText,
        val keyPem: EditText, val passphrase: EditText,
        val rbDocker: RadioButton, val serverIp: EditText, val serverPort: EditText,
        val binaryUrl: EditText,
    )

    /**
     * Copies the currently-displayed Step 1 widget values into the instance fields
     * WITHOUT validating or navigating — used before backgrounding into the system file
     * picker ([pickBinaryFile]) so [onBinaryFilePicked]'s `renderStep()` rebuilds the
     * form from up-to-date state instead of silently reverting every other field the
     * user had already typed back to whatever [buildTargetStep] was last called with.
     * [onTargetNext] duplicates this read (plus validation) rather than calling through,
     * since it must not silently accept a still-invalid form.
     */
    private fun syncTargetFieldsFromViews() {
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
        binaryUrl = v.binaryUrl.text.toString().trim()
    }

    private fun onTargetNext() {
        syncTargetFieldsFromViews()

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
        if (binarySource == BinarySource.URL && binaryUrl.isEmpty()) {
            Toast.makeText(this, getString(R.string.install_error_need_binary_url), Toast.LENGTH_SHORT).show()
            return
        }
        if (binarySource == BinarySource.FILE && binaryFilePath == null) {
            Toast.makeText(this, getString(R.string.install_error_need_binary_file), Toast.LENGTH_SHORT).show()
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

    /**
     * Handles the SAF [pickBinaryFile] result: copies the picked content into
     * [cacheDir] under a private, process-visible path, since the Rust installer
     * (`tokio::fs::read` in `aivpn-common::ssh_install::run_install`) needs a real
     * filesystem path to open — a `content://` Uri from [ActivityResultContracts.GetContent]
     * is not guaranteed to resolve to one (e.g. a cloud-backed document provider), so it
     * cannot be handed to the JNI layer directly.
     */
    private fun onBinaryFilePicked(uri: Uri) {
        lifecycleScope.launch {
            val (path, name) = withContext(Dispatchers.IO) { copyPickedBinaryToCache(uri) }
            if (path != null) {
                // Drop the previous copy (if the user picked a file more than once) so
                // repeated picks don't silently accumulate full binary copies in cache.
                val previous = binaryFilePath
                binaryFilePath = path
                binaryFileName = name
                if (previous != null && previous != path) {
                    withContext(Dispatchers.IO) { try { java.io.File(previous).delete() } catch (_: Throwable) { } }
                }
            } else {
                Toast.makeText(this@InstallServerActivity, getString(R.string.install_error_file_read_failed), Toast.LENGTH_SHORT).show()
            }
            if (step == Step.TARGET) renderStep()
        }
    }

    private fun copyPickedBinaryToCache(uri: Uri): Pair<String?, String> {
        val name = queryDisplayName(uri) ?: "aivpn-server"
        return try {
            val dest = java.io.File(cacheDir, "ssh-install-binary-${UUID.randomUUID()}")
            val copied = contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
                true
            } ?: false
            if (copied) dest.absolutePath to name else null to name
        } catch (t: Throwable) {
            android.util.Log.e("InstallServerActivity", "failed to copy picked binary", t)
            null to name
        }
    }

    private fun queryDisplayName(uri: Uri): String? = try {
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) cursor.getString(idx) else null
            } else {
                null
            }
        }
    } catch (t: Throwable) {
        android.util.Log.e("InstallServerActivity", "failed to query display name", t)
        null
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
        pollJob = lifecycleScope.launch {
            // Derive the device pubkey (if binding is requested) off the main thread —
            // see [devicePubkeyBase64]'s doc comment for why this can't just be null.
            val devicePubkeyB64: String? = if (deviceBinding) {
                withContext(Dispatchers.IO) { devicePubkeyBase64() }
            } else {
                null
            }
            if (deviceBinding && devicePubkeyB64 == null) {
                // Honest failure rather than silently installing an unbound admin
                // client while the user believes binding is on (see G4 in the task —
                // no fabricated fallback).
                appendLog(getString(R.string.install_device_binding_failed))
                installFinished = true
                finishedExitCode = -1
                renderStep()
                return@launch
            }
            val paramsJson = buildParamsJson(fingerprint, devicePubkeyB64)
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
     * Reads this device's JIT-enrollment private key ([SecureStorage.loadDeviceKey]),
     * generating and persisting one first if this device has never run a tunnel session
     * yet (mirrors [AivpnService]'s lazy-generate — see its `runTunnel` call site — so
     * the SAME key is reused later for the actual JIT enrollment DH regardless of
     * whether install-wizard binding or a real VPN connect happens first), then derives
     * the matching X25519 public key via [AivpnJni.devicePubkey].
     *
     * @return base64 STANDARD-encoded public key, or `null` if the core is unavailable
     *         or [AivpnJni.devicePubkey] itself fails (should not normally happen since
     *         this always feeds it a well-formed 32-byte key). Never throws.
     */
    private fun devicePubkeyBase64(): String? {
        if (!AivpnJni.isAvailable) return null
        val privkey = SecureStorage.loadDeviceKey(this) ?: ByteArray(32).also { bytes ->
            java.security.SecureRandom().nextBytes(bytes)
            SecureStorage.saveDeviceKey(this, bytes)
        }
        val privkeyB64 = android.util.Base64.encodeToString(privkey, android.util.Base64.NO_WRAP)
        return try {
            AivpnJni.devicePubkey(privkeyB64)
        } catch (t: Throwable) {
            android.util.Log.e("InstallServerActivity", "devicePubkey failed", t)
            null
        }
    }

    /**
     * Wire contract shared with `aivpn_common::ssh_install::install_params_from_json`
     * (see that function's doc comment / crates/aivpn-common/src/ssh_install.rs).
     *
     * @param devicePubkeyB64 result of [devicePubkeyBase64], or `null` when the user did
     *                        not opt into device binding — either way sent through as-is
     *                        (`null` becomes JSON `null`, matching the field's optional
     *                        wire contract).
     */
    private fun buildParamsJson(fingerprint: String, devicePubkeyB64: String?): String {
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
        val binaryObj = when (binarySource) {
            BinarySource.DEFAULT -> JSONObject().put("type", "default")
            BinarySource.URL -> JSONObject().put("type", "url").put("url", binaryUrl)
            // binaryFilePath is validated non-null in onTargetNext() before this step
            // is ever reachable — see the wire contract in
            // aivpn_common::ssh_install::install_params_from_json.
            BinarySource.FILE -> JSONObject().put("type", "file").put("path", binaryFilePath)
        }
        root.put("binary", binaryObj)
        if (serverIp.isNotEmpty()) root.put("server_ip", serverIp)
        serverPort.toIntOrNull()?.let { root.put("server_port", it) }
        root.put("mode", if (modeIsDocker) "docker" else "systemd")
        root.put("device_pubkey_b64", devicePubkeyB64 ?: JSONObject.NULL)
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
