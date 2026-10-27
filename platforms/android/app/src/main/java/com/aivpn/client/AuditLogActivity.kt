package com.aivpn.client

import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aivpn.client.databinding.ActivityAuditLogBinding
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/**
 * Read-only audit-log view (G-A2): the append-only, hash-chain-verified
 * admin-action log served by `GET /api/v1/audit-log?verify=1` over the
 * already-active tunnel session via [AdminApi.auditLog] — same
 * "no separate admin connection" caveat as [AdminActivity]/[PoolActivity]
 * (surfaced via [textNotConnected] when the VPN isn't up).
 *
 * Never mutates anything, so it is reachable for BOTH Viewer and Admin
 * roles — the entry point button lives in [AdminActivity]'s toolbar, which
 * is itself already gated to Viewer+Admin by [MainActivity]'s menu
 * visibility check (`AivpnJni.getRole() >= 1`).
 */
class AuditLogActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAuditLogBinding
    private val loader = ScreenLoader()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuditLogBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }
        binding.btnRefresh.setOnClickListener { load() }
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        lifecycleScope.launch {
            loader.load currentLoad@{ isCurrent ->
                binding.btnRefresh.isEnabled = false
                try {
                    val result = AdminApi.auditLog()
                    if (!isCurrent()) return@currentLoad
                    val obj = if (result.ok) result.bodyObject() else null
                    val entries = if (result.ok) obj?.optJSONArray("entries") ?: result.bodyArray() else null
                    if (entries == null) {
                        binding.textNotConnected.text = managementErrorMessage(result)
                        binding.textNotConnected.visibility = View.VISIBLE
                        binding.textChainStatus.visibility = View.GONE
                        binding.textEmpty.visibility = View.GONE
                        binding.containerEntries.removeAllViews()
                        return@currentLoad
                    }
                    binding.textNotConnected.visibility = View.GONE
                    val verified = if (obj?.has("verified") == true) obj.optBoolean("verified", false) else null
                    val brokenAt = if (obj == null || obj.isNull("broken_at")) null else obj.optInt("broken_at")
                    renderChainStatus(verified, brokenAt)
                    renderEntries(entries)
                } finally {
                    binding.btnRefresh.isEnabled = true
                }
            }
        }
    }

    private fun renderChainStatus(verified: Boolean?, brokenAt: Int?) {
        if (verified == null) {
            binding.textChainStatus.visibility = View.GONE
            return
        }
        binding.textChainStatus.visibility = View.VISIBLE
        if (verified) {
            binding.textChainStatus.text = getString(R.string.audit_chain_verified)
            binding.textChainStatus.setTextColor(getColor(R.color.green))
            binding.textChainStatus.setBackgroundColor(getColor(R.color.green_container))
        } else {
            binding.textChainStatus.text = getString(R.string.audit_chain_broken, brokenAt ?: 0)
            binding.textChainStatus.setTextColor(colorAttr(com.google.android.material.R.attr.colorError, R.color.disconnect))
            binding.textChainStatus.setBackgroundColor(getColor(R.color.error_container))
        }
    }

    private fun renderEntries(arr: JSONArray?) {
        binding.containerEntries.removeAllViews()
        val count = arr?.length() ?: 0
        binding.textEmpty.visibility = if (count == 0) View.VISIBLE else View.GONE

        // Newest first: the server returns oldest-first (chain order), so
        // reverse for display — same convention as desktop admin panels.
        for (i in count - 1 downTo 0) {
            val entry = arr?.optJSONObject(i) ?: continue
            binding.containerEntries.addView(buildEntryRow(entry))
        }
    }

    private fun buildEntryRow(entry: JSONObject): View {
        val ts = entry.optString("ts", "")
        val actor = entry.optString("actor", "")
        val action = entry.optString("action", "")
        val target = entry.optString("target", "")
        val result = entry.optString("result", "")
        val ok = result == "ok"

        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(20.dp, 8.dp, 20.dp, 0)
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16.dp, 16.dp, 16.dp, 16.dp)
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(12.dp, 12.dp).apply { marginEnd = 10.dp }
            setBackgroundResource(if (ok) R.drawable.dot_green else R.drawable.dot_grey)
        })
        header.addView(TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            text = if (action.isNotBlank()) action else "?"
            textSize = 16f
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
            maxLines = 2
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        header.addView(TextView(this).apply {
            text = result
            textSize = 14f
            setTextColor(
                if (ok) getColor(R.color.green)
                else colorAttr(com.google.android.material.R.attr.colorError, R.color.disconnect)
            )
        })
        content.addView(header)

        content.addView(TextView(this).apply {
            text = getString(R.string.audit_entry_actor_prefix, ts, actor)
            textSize = 14f
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurfaceVariant, R.color.text_secondary))
            setPadding(0, 4.dp, 0, 0)
        })

        if (target.isNotBlank()) {
            content.addView(TextView(this).apply {
                text = getString(R.string.audit_entry_target_prefix, target)
                textSize = 14f
                setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurfaceVariant, R.color.text_secondary))
                setPadding(0, 4.dp, 0, 0)
                maxLines = 4
                ellipsize = android.text.TextUtils.TruncateAt.END
            })
        }

        card.addView(content)
        return card
    }

    private fun colorAttr(attr: Int, fallback: Int): Int {
        val typed = android.util.TypedValue()
        return if (theme.resolveAttribute(attr, typed, true)) {
            if (typed.resourceId != 0) getColor(typed.resourceId) else typed.data
        } else {
            getColor(fallback)
        }
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
