package com.aivpn.client

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.View
import android.widget.PopupMenu
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.aivpn.client.databinding.ItemProfileBinding

class ProfilesAdapter(
    private val onProfileClick: (SecureStorage.ConnectionProfile) -> Unit,
    private val onEditClick:    (SecureStorage.ConnectionProfile) -> Unit,
    private val onDeleteClick:  (SecureStorage.ConnectionProfile) -> Unit,
) : ListAdapter<SecureStorage.ConnectionProfile, ProfilesAdapter.ViewHolder>(DIFF_CALLBACK) {

    var activeProfileId: String? = null
        set(value) {
            field = value
            notifyItemRangeChanged(0, itemCount)
        }
    var editingEnabled: Boolean = true
        set(value) {
            if (field == value) return
            field = value
            notifyItemRangeChanged(0, itemCount)
        }

    inner class ViewHolder(val binding: ItemProfileBinding) :
        RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemProfileBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val profile = getItem(position)
        val isActive = profile.id == activeProfileId
        with(holder.binding) {
            profileName.text   = profile.name
            profileServer.text = ConnectionKeyParser.serverAddrFrom(profile.key)
            profileName.setTypeface(
                null,
                Typeface.NORMAL
            )
            profileSelected.visibility = if (isActive) View.VISIBLE else View.GONE
            root.setCardBackgroundColor(UiAppearance.color(root.context,
                if (isActive) com.google.android.material.R.attr.colorPrimaryContainer
                else com.google.android.material.R.attr.colorSurfaceContainer))
            root.isEnabled = editingEnabled
            root.setOnClickListener { onProfileClick(profile) }
            btnMore.isEnabled = editingEnabled
            btnMore.contentDescription = root.context.getString(R.string.ui_profile_actions, profile.name)
            btnMore.setOnClickListener { anchor ->
                if (!editingEnabled) return@setOnClickListener
                PopupMenu(root.context, anchor).apply {
                    menu.add(0, 1, 0, R.string.btn_edit)
                    menu.add(0, 2, 1, R.string.btn_delete)
                    setOnMenuItemClickListener { item ->
                        if (editingEnabled) {
                            if (item.itemId == 1) onEditClick(profile) else onDeleteClick(profile)
                        }
                        true
                    }
                }.show()
            }
        }
    }

    companion object {
        val DIFF_CALLBACK = object : DiffUtil.ItemCallback<SecureStorage.ConnectionProfile>() {
            override fun areItemsTheSame(
                a: SecureStorage.ConnectionProfile,
                b: SecureStorage.ConnectionProfile,
            ) = a.id == b.id

            override fun areContentsTheSame(
                a: SecureStorage.ConnectionProfile,
                b: SecureStorage.ConnectionProfile,
            ) = a == b
        }
    }
}
