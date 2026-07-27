package com.aivpn.client

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aivpn.client.databinding.ActivityMigrationBinding
import kotlinx.coroutines.launch

/**
 * Server-migration guide (C3): export the old server's backup, install a new
 * server via [InstallServerActivity], then import the backup into the new
 * server. Three sequential steps in one screen, each just explanatory copy
 * plus one action button — this is a GUIDE, not an automated pipeline (the
 * user is expected to actually be connected to the OLD server's mgmt tunnel
 * during export, and to the NEW one during import; nothing here re-points
 * the active connection profile automatically).
 *
 * Both backup calls go through [AdminApi.exportBackupRaw] /
 * [AdminApi.importBackupRaw] — real [AivpnJni.mgmtRequest] calls, no mocks.
 *
 * **Known gap (see [AdminApi]'s doc comment on those two methods)**: the
 * server's curated in-tunnel allowlist (`mgmt_service.rs::classify_route`)
 * does not currently include `/api/v1/backup/export` or
 * `/api/v1/backup/import` — only the full REST surface (Unix socket /
 * aivpn-web) has them. Until that allowlist is extended, both steps below
 * will get rejected by the server (non-2xx or empty result) even against a
 * fully-Admin, fully-connected session. This screen surfaces whatever the
 * server actually returns rather than assuming success.
 */
class MigrationActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMigrationBinding

    private enum class Step { EXPORT, INSTALL, IMPORT }
    private var step = Step.EXPORT

    private var exportedBytes: ByteArray? = null

    private val pickBackupFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) importFromUri(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMigrationBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }
        renderStep()
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    private fun renderStep() {
        binding.contentContainer.removeAllViews()
        when (step) {
            Step.EXPORT -> binding.contentContainer.addView(buildExportStep())
            Step.INSTALL -> binding.contentContainer.addView(buildInstallStep())
            Step.IMPORT -> binding.contentContainer.addView(buildImportStep())
        }
    }

    private fun sectionLayout(): LinearLayout =
        LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

    private fun titleView(res: Int): TextView = TextView(this).apply {
        text = getString(res)
        textSize = 16f
        setTypeface(typeface, android.graphics.Typeface.BOLD)
        setTextColor(getColor(R.color.text_primary))
        setPadding(0, 0, 0, 6.dp)
    }

    private fun bodyView(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 13f
        setTextColor(getColor(R.color.text_secondary))
        setPadding(0, 0, 0, 12.dp)
    }

    private fun statusView(): TextView = TextView(this).apply {
        textSize = 12f
        setTextColor(getColor(R.color.text_secondary))
        setTextIsSelectable(true)
        setPadding(0, 8.dp, 0, 0)
    }

    private fun nextButton(labelRes: Int, action: () -> Unit): Button =
        Button(this).apply {
            text = getString(labelRes)
            setOnClickListener { action() }
        }

    // ──────────── Step 1: export ────────────

    private fun buildExportStep(): View {
        val layout = sectionLayout()
        layout.addView(titleView(R.string.migrate_step1_title))
        layout.addView(bodyView(getString(R.string.migrate_step1_body)))

        val status = statusView()
        val exportBtn = Button(this).apply { text = getString(R.string.migrate_export_backup) }
        exportBtn.setOnClickListener {
            exportBtn.isEnabled = false
            status.text = getString(R.string.migrate_working)
            lifecycleScope.launch {
                val (code, bytes) = AdminApi.exportBackupRaw()
                exportBtn.isEnabled = true
                when {
                    code == 0 -> status.text = getString(R.string.admin_not_connected)
                    code in 200..299 && bytes.isNotEmpty() -> {
                        exportedBytes = bytes
                        status.text = getString(R.string.migrate_export_ok, bytes.size)
                        shareExportedBackup(bytes)
                    }
                    else -> status.text = getString(R.string.migrate_export_failed, code)
                }
            }
        }
        layout.addView(exportBtn)
        layout.addView(status)
        layout.addView(nextButton(R.string.migrate_step_next) { step = Step.INSTALL; renderStep() })
        return layout
    }

    private fun shareExportedBackup(bytes: ByteArray) {
        try {
            val file = java.io.File(cacheDir, "aivpn-backup.tar.gz")
            file.writeBytes(bytes)
            val uri = androidx.core.content.FileProvider.getUriForFile(this, "${packageName}.provider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/gzip"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, getString(R.string.migrate_export_backup)))
        } catch (t: Throwable) {
            android.util.Log.e("MigrationActivity", "failed to share exported backup", t)
        }
    }

    // ──────────── Step 2: install ────────────

    private fun buildInstallStep(): View {
        val layout = sectionLayout()
        layout.addView(titleView(R.string.migrate_step2_title))
        layout.addView(bodyView(getString(R.string.migrate_step2_body)))
        layout.addView(Button(this).apply {
            text = getString(R.string.migrate_open_install_wizard)
            setOnClickListener { startActivity(Intent(this@MigrationActivity, InstallServerActivity::class.java)) }
        })
        layout.addView(nextButton(R.string.migrate_step_next) { step = Step.IMPORT; renderStep() })
        return layout
    }

    // ──────────── Step 3: import ────────────

    private fun buildImportStep(): View {
        val layout = sectionLayout()
        layout.addView(titleView(R.string.migrate_step3_title))
        layout.addView(bodyView(getString(R.string.migrate_step3_body)))

        val status = statusView()
        layout.addView(Button(this).apply {
            text = getString(R.string.migrate_pick_backup_file)
            setOnClickListener { pickBackupFile.launch("application/gzip") }
        })
        this.importStatusView = status
        layout.addView(status)
        layout.addView(Button(this).apply {
            text = getString(R.string.migrate_finish)
            setOnClickListener { finish() }
        })
        return layout
    }

    private var importStatusView: TextView? = null

    private fun importFromUri(uri: Uri) {
        val status = importStatusView
        status?.text = getString(R.string.migrate_working)
        lifecycleScope.launch {
            val bytes = try {
                contentResolver.openInputStream(uri)?.use { it.readBytes() }
            } catch (t: Throwable) {
                android.util.Log.e("MigrationActivity", "failed to read backup file", t)
                null
            }
            if (bytes == null) {
                status?.text = getString(R.string.migrate_import_read_failed)
                return@launch
            }
            val (code, _) = AdminApi.importBackupRaw(bytes)
            status?.text = when {
                code == 0 -> getString(R.string.admin_not_connected)
                code in 200..299 -> getString(R.string.migrate_import_ok)
                else -> getString(R.string.migrate_import_failed, code)
            }
        }
    }
}
