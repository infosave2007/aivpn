package com.aivpn.client

import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAuditLogBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }
        binding.btnRefresh.setOnClickListener { load() }

        load()
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        lifecycleScope.launch {
            val result = AdminApi.auditLog()
            if (result.notConnected) {
                binding.textNotConnected.visibility = View.VISIBLE
                binding.textChainStatus.visibility = View.GONE
                binding.textEmpty.visibility = View.GONE
                binding.containerEntries.removeAllViews()
                return@launch
            }
            binding.textNotConnected.visibility = View.GONE

            if (!result.ok) {
                Toast.makeText(
                    this@AuditLogActivity,
                    getString(R.string.admin_error_generic, result.status),
                    Toast.LENGTH_SHORT
                ).show()
                return@launch
            }

            // `?verify=1` shape is `{"entries":[...],"verified":bool,"broken_at":usize|null}`
            // (server-side mgmt_service::AuditVerifyView). Tolerate a bare
            // entries array too (older server / no verify param honored),
            // in which case chain status is simply not shown.
            val obj = result.bodyObject()
            val entries: JSONArray?
            val verified: Boolean?
            val brokenAt: Int?
            if (obj != null) {
                entries = obj.optJSONArray("entries")
                verified = if (obj.has("verified")) obj.optBoolean("verified", false) else null
                brokenAt = if (obj.isNull("broken_at") || !obj.has("broken_at")) null else obj.optInt("broken_at")
            } else {
                entries = result.bodyArray()
                verified = null
                brokenAt = null
            }

            renderChainStatus(verified, brokenAt)
            renderEntries(entries)
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
        } else {
            binding.textChainStatus.text = getString(R.string.audit_chain_broken, brokenAt ?: 0)
            binding.textChainStatus.setTextColor(getColor(R.color.disconnect))
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
                setMargins(12.dp, 6.dp, 12.dp, 0)
            }
            setCardBackgroundColor(getColor(R.color.surface))
            radius = 16f.dp
            cardElevation = 0f
            strokeWidth = 0
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(14.dp, 14.dp, 14.dp, 14.dp)
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(View(this).apply {
            layoutParams = LinearLayout.LayoutParams(10.dp, 10.dp).apply { marginEnd = 10.dp }
            setBackgroundResource(if (ok) R.drawable.dot_green else R.drawable.dot_grey)
        })
        header.addView(TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            text = if (action.isNotBlank()) action else "?"
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(getColor(R.color.text_primary))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        header.addView(TextView(this).apply {
            text = result
            textSize = 11f
            setTextColor(if (ok) getColor(R.color.green) else getColor(R.color.disconnect))
        })
        content.addView(header)

        content.addView(TextView(this).apply {
            text = getString(R.string.audit_entry_actor_prefix, ts, actor)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 4.dp, 0, 0)
        })

        if (target.isNotBlank()) {
            content.addView(TextView(this).apply {
                text = getString(R.string.audit_entry_target_prefix, target)
                textSize = 12f
                setTextColor(getColor(R.color.text_secondary))
                setPadding(0, 2.dp, 0, 0)
                maxLines = 3
                ellipsize = android.text.TextUtils.TruncateAt.END
            })
        }

        card.addView(content)
        return card
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
    private val Float.dp: Float get() = this * resources.displayMetrics.density
}
