package com.aivpn.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.aivpn.client.databinding.ActivityAdminBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * In-app client-management screen (P3.1). Talks to the curated management
 * API on the server over the ALREADY-ACTIVE tunnel session via [AdminApi] —
 * there is no separate admin connection, so every action here requires the
 * VPN to be connected (surfaced via [textNotConnected] when it is not).
 *
 * Visibility of the entry point in [MainActivity] and the role check here
 * are both driven by [AivpnJni.getRole]: 2=Admin gets full read/write,
 * 1=Viewer gets a read-only list (no add/edit/reset/revoke), 0=User never
 * sees this screen at all. Role assignment itself is server-side only and
 * is intentionally not exposed anywhere in this screen.
 */
class AdminActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAdminBinding
    private lateinit var adapter: ClientAdapter
    private val clients = mutableListOf<JSONObject>()
    private var isAdmin = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAdminBinding.inflate(layoutInflater)
        setContentView(binding.root)

        isAdmin = try {
            AivpnJni.isAvailable && AivpnJni.getRole() == ROLE_ADMIN
        } catch (_: Throwable) {
            false
        }

        adapter = ClientAdapter()
        binding.recyclerClients.layoutManager = LinearLayoutManager(this)
        binding.recyclerClients.adapter = adapter

        binding.btnBack.setOnClickListener { finish() }
        binding.btnRefresh.setOnClickListener { loadClients() }
        binding.fabAdd.visibility = if (isAdmin) View.VISIBLE else View.GONE
        binding.fabAdd.setOnClickListener { showAddDialog() }

        loadClients()
    }

    override fun onResume() {
        super.onResume()
        loadClients()
    }

    // ──────────── Loading ────────────

    private fun loadClients() {
        lifecycleScope.launch {
            val result = AdminApi.listClients()
            if (result.notConnected) {
                binding.textNotConnected.visibility = View.VISIBLE
                binding.textEmpty.visibility = View.GONE
                clients.clear()
                adapter.notifyDataSetChanged()
                return@launch
            }
            binding.textNotConnected.visibility = View.GONE

            if (!result.ok) {
                Toast.makeText(
                    this@AdminActivity,
                    getString(R.string.admin_error_generic, result.status),
                    Toast.LENGTH_SHORT
                ).show()
                return@launch
            }

            val arr = result.bodyArray()
            clients.clear()
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    clients.add(arr.optJSONObject(i) ?: continue)
                }
            }
            binding.textEmpty.visibility = if (clients.isEmpty()) View.VISIBLE else View.GONE
            adapter.notifyDataSetChanged()
        }
    }

    // ──────────── Add ────────────

    private fun showAddDialog() {
        if (!isAdmin) return
        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)
        val layout = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }
        val nameInput = EditText(dialogCtx).apply {
            hint = getString(R.string.admin_hint_name)
            setSingleLine(true)
        }
        val oneTimeCheck = CheckBox(dialogCtx).apply {
            text = getString(R.string.admin_one_time)
        }
        val expiryLabel = TextView(dialogCtx).apply {
            text = getString(R.string.admin_hint_expiry)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }
        val expiryInput = EditText(dialogCtx).apply {
            hint = "2026-12-31T00:00:00Z"
            setSingleLine(true)
            textSize = 13f
        }
        layout.addView(nameInput)
        layout.addView(oneTimeCheck)
        layout.addView(expiryLabel)
        layout.addView(expiryInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.admin_dialog_add_title))
            .setView(layout)
            .setPositiveButton(getString(R.string.btn_save)) { _, _ ->
                val name = nameInput.text.toString().trim()
                if (name.isEmpty()) {
                    Toast.makeText(this, getString(R.string.admin_hint_name), Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val expiry = expiryInput.text.toString().trim()
                lifecycleScope.launch {
                    val result = AdminApi.addClient(name, oneTimeCheck.isChecked, expiry.ifEmpty { null })
                    handleMutationResult(result)
                }
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    // ──────────── Edit ────────────

    private fun showEditDialog(client: JSONObject) {
        if (!isAdmin) return
        val id = client.optString("id", client.optString("client_id", ""))
        if (id.isEmpty()) return

        val dialogCtx = android.view.ContextThemeWrapper(this, R.style.Theme_AIVPN_Dialog)
        val layout = LinearLayout(dialogCtx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 16.dp, 24.dp, 0)
        }
        val nameInput = EditText(dialogCtx).apply {
            hint = getString(R.string.admin_hint_name)
            setText(client.optString("name", ""))
            setSingleLine(true)
        }
        val enabledCheck = CheckBox(dialogCtx).apply {
            text = getString(R.string.admin_enabled)
            isChecked = client.optBoolean("enabled", true)
        }
        val oneTimeCheck = CheckBox(dialogCtx).apply {
            text = getString(R.string.admin_one_time)
            isChecked = client.optBoolean("one_time", false)
        }
        val expiryLabel = TextView(dialogCtx).apply {
            text = getString(R.string.admin_hint_expiry)
            textSize = 12f
            setTextColor(getColor(R.color.text_secondary))
            setPadding(0, 8.dp, 0, 2.dp)
        }
        val expiryInput = EditText(dialogCtx).apply {
            hint = "2026-12-31T00:00:00Z"
            setText(client.optString("expires_at", ""))
            setSingleLine(true)
            textSize = 13f
        }
        layout.addView(nameInput)
        layout.addView(enabledCheck)
        layout.addView(oneTimeCheck)
        layout.addView(expiryLabel)
        layout.addView(expiryInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.admin_dialog_edit_title))
            .setView(layout)
            .setPositiveButton(getString(R.string.btn_save)) { _, _ ->
                val name = nameInput.text.toString().trim()
                val expiry = expiryInput.text.toString().trim()
                lifecycleScope.launch {
                    val result = AdminApi.patchClient(
                        id = id,
                        name = name.ifEmpty { null },
                        enabled = enabledCheck.isChecked,
                        oneTime = oneTimeCheck.isChecked,
                        expiresAt = expiry,
                    )
                    handleMutationResult(result)
                }
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    // ──────────── Connection key / QR ────────────

    private fun showKeyDialog(id: String, name: String) {
        lifecycleScope.launch {
            val result = AdminApi.connectionKey(id)
            if (result.notConnected) {
                Toast.makeText(this@AdminActivity, getString(R.string.admin_not_connected), Toast.LENGTH_SHORT).show()
                return@launch
            }
            if (!result.ok) {
                Toast.makeText(
                    this@AdminActivity,
                    getString(R.string.admin_error_generic, result.status),
                    Toast.LENGTH_SHORT
                ).show()
                return@launch
            }
            val key = result.bodyObject()?.optString("connection_key", "") ?: ""
            if (key.isEmpty()) {
                Toast.makeText(this@AdminActivity, getString(R.string.admin_error_generic, result.status), Toast.LENGTH_SHORT).show()
                return@launch
            }

            val bitmap: Bitmap? = withContext(Dispatchers.IO) {
                try {
                    if (!AivpnJni.isAvailable) return@withContext null
                    val png = AivpnJni.qrPng(key)
                    if (png.isEmpty()) null else BitmapFactory.decodeByteArray(png, 0, png.size)
                } catch (t: Throwable) {
                    android.util.Log.e("AdminActivity", "qrPng failed", t)
                    null
                }
            }

            val dialogCtx = android.view.ContextThemeWrapper(this@AdminActivity, R.style.Theme_AIVPN_Dialog)
            val layout = LinearLayout(dialogCtx).apply {
                orientation = LinearLayout.VERTICAL
                gravity = android.view.Gravity.CENTER_HORIZONTAL
                setPadding(24.dp, 16.dp, 24.dp, 0)
            }
            if (bitmap != null) {
                layout.addView(ImageView(dialogCtx).apply {
                    setImageBitmap(bitmap)
                    layoutParams = LinearLayout.LayoutParams(220.dp, 220.dp)
                })
            }
            layout.addView(TextView(dialogCtx).apply {
                text = key
                textSize = 11f
                setTextColor(getColor(R.color.text_secondary))
                setPadding(0, 12.dp, 0, 0)
                setTextIsSelectable(true)
            })

            AlertDialog.Builder(this@AdminActivity)
                .setTitle(name)
                .setView(layout)
                .setPositiveButton(getString(R.string.admin_share)) { _, _ ->
                    val sendIntent = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, key)
                    }
                    startActivity(Intent.createChooser(sendIntent, getString(R.string.admin_share)))
                }
                .setNeutralButton(getString(R.string.admin_copy)) { _, _ ->
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("connection_key", key))
                    Toast.makeText(this@AdminActivity, getString(R.string.admin_copied), Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(getString(R.string.btn_cancel), null)
                .show()
        }
    }

    // ──────────── Reset device ────────────

    private fun confirmReset(id: String, name: String) {
        if (!isAdmin) return
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.admin_reset_confirm_title))
            .setMessage(getString(R.string.admin_reset_confirm_msg, name))
            .setPositiveButton(getString(R.string.admin_action_reset)) { _, _ ->
                lifecycleScope.launch {
                    val result = AdminApi.resetDevice(id)
                    handleMutationResult(result)
                }
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    // ──────────── Revoke ────────────

    private fun confirmRevoke(id: String, name: String) {
        if (!isAdmin) return
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.admin_revoke_confirm_title))
            .setMessage(getString(R.string.admin_revoke_confirm_msg, name))
            .setPositiveButton(getString(R.string.admin_action_revoke)) { _, _ ->
                lifecycleScope.launch {
                    val result = AdminApi.revoke(id)
                    handleMutationResult(result)
                }
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    // ──────────── Shared mutation result handling ────────────

    private fun handleMutationResult(result: MgmtResult) {
        when {
            result.notConnected -> Toast.makeText(this, getString(R.string.admin_not_connected), Toast.LENGTH_SHORT).show()
            result.ok -> loadClients()
            else -> {
                val reason = result.bodyObject()?.optString("reason")
                    ?: result.bodyObject()?.optString("error")
                val msg = if (!reason.isNullOrBlank()) {
                    getString(R.string.admin_error_with_reason, result.status, reason)
                } else {
                    getString(R.string.admin_error_generic, result.status)
                }
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
            }
        }
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    // ──────────── Adapter ────────────

    inner class ClientAdapter : RecyclerView.Adapter<ClientAdapter.VH>() {

        inner class VH(parent: ViewGroup) : RecyclerView.ViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_admin_client, parent, false)
        ) {
            val dot: View = itemView.findViewById(R.id.dotStatus)
            val name: TextView = itemView.findViewById(R.id.textName)
            val role: TextView = itemView.findViewById(R.id.textRole)
            val subtitle: TextView = itemView.findViewById(R.id.textSubtitle)
            val reject: TextView = itemView.findViewById(R.id.textReject)
            val rowActions: LinearLayout = itemView.findViewById(R.id.rowActions)
            val btnKey: TextView = itemView.findViewById(R.id.btnKey)
            val btnEdit: TextView = itemView.findViewById(R.id.btnEdit)
            val btnReset: TextView = itemView.findViewById(R.id.btnReset)
            val btnRevoke: TextView = itemView.findViewById(R.id.btnRevoke)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(parent)
        override fun getItemCount() = clients.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val c = clients[position]
            val id = c.optString("id", c.optString("client_id", ""))
            val name = c.optString("name", id)
            val enabled = c.optBoolean("enabled", true)
            val oneTime = c.optBoolean("one_time", false)
            val expiresAt = c.optString("expires_at", "")
            val roleStr = c.optString("role", "")
            val rejectReason = c.optString("reject_reason", c.optString("last_reject_reason", ""))

            holder.name.text = name
            holder.dot.setBackgroundResource(if (enabled) R.drawable.dot_green else R.drawable.dot_grey)

            if (roleStr.isNotBlank()) {
                holder.role.text = roleStr
                holder.role.visibility = View.VISIBLE
            } else {
                holder.role.visibility = View.GONE
            }

            val parts = mutableListOf<String>()
            parts.add(
                if (enabled) getString(R.string.admin_status_enabled)
                else getString(R.string.admin_status_disabled)
            )
            if (oneTime) parts.add(getString(R.string.admin_status_one_time))
            if (expiresAt.isNotBlank()) parts.add(getString(R.string.admin_status_expires, expiresAt))
            holder.subtitle.text = parts.joinToString("  •  ")

            if (rejectReason.isNotBlank()) {
                holder.reject.text = getString(R.string.admin_reject_reason_prefix, rejectReason)
                holder.reject.visibility = View.VISIBLE
            } else {
                holder.reject.visibility = View.GONE
            }

            if (id.isEmpty()) {
                holder.rowActions.visibility = View.GONE
                return
            }

            // Viewer (role==1): read-only list, no key/edit/reset/revoke actions.
            if (!isAdmin) {
                holder.rowActions.visibility = View.GONE
                return
            }
            holder.rowActions.visibility = View.VISIBLE

            holder.btnKey.setOnClickListener { showKeyDialog(id, name) }
            holder.btnEdit.setOnClickListener { showEditDialog(c) }
            holder.btnReset.setOnClickListener { confirmReset(id, name) }
            holder.btnRevoke.setOnClickListener { confirmRevoke(id, name) }
        }
    }

    companion object {
        private const val ROLE_ADMIN = 2
    }
}
