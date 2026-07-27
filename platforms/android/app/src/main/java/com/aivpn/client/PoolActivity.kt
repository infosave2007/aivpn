package com.aivpn.client

import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aivpn.client.databinding.ActivityPoolBinding
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Read-only pool topology view (Wave B3-Android): the node list from
 * `GET /api/v1/pool/nodes` plus the aggregate summary from
 * `GET /api/v1/pool/health`, both over the already-active tunnel session
 * via [AdminApi] — same "no separate admin connection" caveat as
 * [AdminActivity] (see [textNotConnected] surfaced when the VPN isn't up).
 *
 * Unlike the rest of the admin section, this screen never mutates
 * anything, so it is reachable for BOTH Viewer and Admin roles — the entry
 * point button lives in [AdminActivity]'s toolbar, which is itself already
 * gated to Viewer+Admin by [MainActivity]'s menu visibility check.
 */
class PoolActivity : AppCompatActivity() {

    private lateinit var binding: ActivityPoolBinding

    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPoolBinding.inflate(layoutInflater)
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
            val nodesResult = AdminApi.poolNodes()
            if (nodesResult.notConnected) {
                binding.textNotConnected.visibility = View.VISIBLE
                binding.cardHealth.visibility = View.GONE
                binding.textWarning.visibility = View.GONE
                binding.textEmpty.visibility = View.GONE
                binding.containerNodes.removeAllViews()
                return@launch
            }
            binding.textNotConnected.visibility = View.GONE

            val healthResult = AdminApi.poolHealth()

            if (!nodesResult.ok) {
                android.widget.Toast.makeText(
                    this@PoolActivity,
                    getString(R.string.admin_error_generic, nodesResult.status),
                    android.widget.Toast.LENGTH_SHORT
                ).show()
                return@launch
            }

            renderHealth(healthResult)
            renderNodes(nodesResult.bodyArray())
        }
    }

    private fun renderHealth(healthResult: MgmtResult) {
        val health = if (healthResult.ok) healthResult.bodyObject() else null
        if (health == null) {
            binding.cardHealth.visibility = View.GONE
            binding.textWarning.visibility = View.GONE
            return
        }
        binding.cardHealth.visibility = View.VISIBLE

        val transport = health.optString("transport", "none")
        val totalNodes = health.optInt("total_nodes", 0)
        val connectedPeers = health.optInt("connected_peers", 0)
        val convergedPeers = health.optInt("converged_peers", 0)
        val diverged = health.optBoolean("diverged", false)
        val partitionConflict = health.optBoolean("partition_conflict", false)
        val subnetMismatch = health.optBoolean("subnet_mismatch", false)

        val lines = mutableListOf(
            getString(R.string.pool_health_transport, transport),
            getString(R.string.pool_health_nodes, totalNodes),
            getString(R.string.pool_health_connected, connectedPeers),
            getString(R.string.pool_health_converged, convergedPeers),
        )
        if (diverged) lines.add(getString(R.string.pool_health_diverged))
        binding.textHealth.text = lines.joinToString("\n")

        if (partitionConflict || subnetMismatch) {
            val reasons = mutableListOf<String>()
            if (partitionConflict) reasons.add(getString(R.string.pool_warning_partition_conflict))
            if (subnetMismatch) reasons.add(getString(R.string.pool_warning_subnet_mismatch))
            binding.textWarning.text = reasons.joinToString("  •  ")
            binding.textWarning.visibility = View.VISIBLE
        } else {
            binding.textWarning.visibility = View.GONE
        }
    }

    private fun renderNodes(arr: JSONArray?) {
        binding.containerNodes.removeAllViews()
        val count = arr?.length() ?: 0
        binding.textEmpty.visibility = if (count == 0) View.VISIBLE else View.GONE

        for (i in 0 until count) {
            val node = arr?.optJSONObject(i) ?: continue
            binding.containerNodes.addView(buildNodeRow(node))
        }
    }

    private fun buildNodeRow(node: JSONObject): View {
        val nodeId = node.optString("node_id", "?")
        val address = if (node.isNull("address")) "" else node.optString("address", "")
        val verified = node.optBoolean("verified", false)
        val revoked = node.optBoolean("revoked", false)
        val connected = node.optBoolean("connected", false)
        val lastSeenUnix = if (node.isNull("last_seen_unix")) null else node.optLong("last_seen_unix")

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
            setBackgroundResource(if (connected) R.drawable.dot_green else R.drawable.dot_grey)
        })
        header.addView(TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            text = nodeId
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setTextColor(getColor(R.color.text_primary))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        if (revoked) {
            header.addView(TextView(this).apply {
                text = getString(R.string.pool_node_revoked)
                textSize = 11f
                setTextColor(getColor(R.color.disconnect))
            })
        }
        content.addView(header)

        val subtitleParts = mutableListOf<String>()
        subtitleParts.add(
            if (address.isNotBlank()) address else getString(R.string.pool_node_no_address)
        )
        subtitleParts.add(
            if (verified) getString(R.string.pool_node_verified)
            else getString(R.string.pool_node_unverified)
        )
        subtitleParts.add(
            if (connected) getString(R.string.pool_node_connected)
            else getString(R.string.pool_node_disconnected)
        )
        content.addView(TextView(this).apply {
            text = subtitleParts.joinToString("  •  ")
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 4.dp, 0, 0)
        })

        content.addView(TextView(this).apply {
            text = getString(
                R.string.pool_node_last_seen,
                if (lastSeenUnix != null) dateFormat.format(Date(lastSeenUnix * 1000)) + " UTC"
                else getString(R.string.pool_node_never)
            )
            textSize = 11f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 2.dp, 0, 0)
        })

        card.addView(content)
        return card
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
    private val Float.dp: Float get() = this * resources.displayMetrics.density
}
