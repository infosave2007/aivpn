package com.aivpn.client

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.CheckBox
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.aivpn.client.databinding.ActivitySplitTunnelBinding
import com.google.android.material.tabs.TabLayout

class SplitTunnelActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplitTunnelBinding

    // Apps
    private lateinit var appAdapter: AppListAdapter
    private var allApps = listOf<AppEntry>()
    private var filteredApps = listOf<AppEntry>()
    private val allowedPackages = mutableSetOf<String>()
    private var hideSystemApps = true
    private var searchQuery = ""

    // Domains
    private lateinit var domainAdapter: DomainListAdapter
    private val excludedDomains = mutableListOf<String>()

    data class AppEntry(
        val name: String,
        val packageName: String,
        val isSystem: Boolean,
        val icon: android.graphics.drawable.Drawable
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySplitTunnelBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }

        // A5: SecureStorage is EncryptedSharedPreferences — Keystore + real disk
        // I/O, hundreds of ms cold — which onCreate must not block on (the same
        // cost BootReceiver moves off its calling thread with goAsync()).
        // Everything below the load stays inside the coroutine on purpose:
        // setupAppsPage/setupSitesPage wire listeners whose handlers persist the
        // in-memory sets, so wiring them over a not-yet-loaded (empty) selection
        // would let one early tap overwrite the stored one.
        lifecycleScope.launch {
            val stored = withContext(Dispatchers.IO) {
                SecureStorage.loadAllowedApps(this@SplitTunnelActivity) to
                    SecureStorage.loadExcludedDomains(this@SplitTunnelActivity)
            }
            allowedPackages.addAll(stored.first)
            excludedDomains.addAll(stored.second)

            setupTabs()
            setupAppsPage()
            setupSitesPage()

            updateCounter()
            loadApps()
        }
    }

    // ──────────── Tabs ────────────

    private fun setupTabs() {
        val tabApps = binding.tabLayout.newTab().setText(getString(R.string.split_tunnel_tab_apps))
        val tabSites = binding.tabLayout.newTab().setText(getString(R.string.split_tunnel_tab_sites))
        binding.tabLayout.addTab(tabApps)
        binding.tabLayout.addTab(tabSites)

        updateTabBadges()

        binding.tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                when (tab.position) {
                    0 -> {
                        binding.pageApps.visibility = View.VISIBLE
                        binding.pageSites.visibility = View.GONE
                    }
                    1 -> {
                        binding.pageApps.visibility = View.GONE
                        binding.pageSites.visibility = View.VISIBLE
                    }
                }
            }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
    }

    private fun updateTabBadges() {
        val appCount = allowedPackages.size
        val domainCount = excludedDomains.size
        binding.tabLayout.getTabAt(0)?.text = if (appCount > 0)
            "${getString(R.string.split_tunnel_tab_apps)} ($appCount)"
        else
            getString(R.string.split_tunnel_tab_apps)
        binding.tabLayout.getTabAt(1)?.text = if (domainCount > 0)
            "${getString(R.string.split_tunnel_tab_sites)} ($domainCount)"
        else
            getString(R.string.split_tunnel_tab_sites)
    }

    // ──────────── Apps page ────────────

    private fun setupAppsPage() {
        appAdapter = AppListAdapter()
        binding.recyclerApps.layoutManager = LinearLayoutManager(this)
        binding.recyclerApps.adapter = appAdapter

        // Search
        binding.editSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                searchQuery = s?.toString()?.trim()?.lowercase() ?: ""
                applyFilter()
            }
        })

        // Hide system apps checkbox
        binding.checkSystem.isChecked = hideSystemApps
        binding.checkSystem.setOnCheckedChangeListener { _, checked ->
            hideSystemApps = checked
            applyFilter()
        }

        // Select all checkbox
        binding.checkAll.setOnCheckedChangeListener(null)
        binding.checkAll.setOnClickListener {
            val shouldSelect = binding.checkAll.isChecked
            if (shouldSelect) {
                for (app in filteredApps) allowedPackages.add(app.packageName)
            } else {
                for (app in filteredApps) allowedPackages.remove(app.packageName)
            }
            saveApps()
            appAdapter.notifyDataSetChanged()
        }
    }

    private fun loadApps() {
        lifecycleScope.launch {
            val pm = packageManager
            val ownPackage = packageName
            val defaultIcon = pm.defaultActivityIcon

            data class LoadResult(val apps: List<AppEntry>, val denied: Boolean)

            val result = withContext(Dispatchers.IO) {
                val flags = if (android.os.Build.VERSION.SDK_INT >= 33) {
                    PackageManager.MATCH_ALL
                } else {
                    0
                }
                val installedApps = try {
                    pm.getInstalledApplications(flags)
                } catch (e: Exception) {
                    android.util.Log.w("SplitTunnelActivity",
                        "getInstalledApplications denied — app list unavailable: ${e.message}")
                    return@withContext LoadResult(emptyList(), denied = true)
                }

                val apps = installedApps
                    .filter { it.packageName != ownPackage }
                    .map { appInfo ->
                        val icon = try { appInfo.loadIcon(pm) } catch (_: Exception) { defaultIcon }
                        AppEntry(
                            name = try { appInfo.loadLabel(pm).toString() } catch (_: Exception) { appInfo.packageName },
                            packageName = appInfo.packageName,
                            isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                                && (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
                            icon = icon
                        )
                    }
                    .distinctBy { it.packageName }
                    .sortedWith(
                        compareBy<AppEntry> { !allowedPackages.contains(it.packageName) }
                            .thenBy { it.name.lowercase() }
                    )
                LoadResult(apps, denied = false)
            }

            if (result.denied) {
                Toast.makeText(this@SplitTunnelActivity,
                    getString(R.string.split_tunnel_apps_unavailable), Toast.LENGTH_LONG).show()
            }
            allApps = result.apps
            applyFilter()
        }
    }

    private fun applyFilter() {
        filteredApps = allApps.filter { app ->
            val matchesSystem = !hideSystemApps || !app.isSystem
            val matchesSearch = searchQuery.isEmpty() ||
                app.name.lowercase().contains(searchQuery) ||
                app.packageName.lowercase().contains(searchQuery)
            matchesSystem && matchesSearch
        }
        appAdapter.notifyDataSetChanged()
        updateSelectAllCheckbox()
    }

    private fun updateSelectAllCheckbox() {
        if (filteredApps.isEmpty()) {
            binding.checkAll.isChecked = false
            return
        }
        val selectedCount = filteredApps.count { allowedPackages.contains(it.packageName) }
        binding.checkAll.setOnCheckedChangeListener(null)
        binding.checkAll.isChecked = selectedCount == filteredApps.size
        // Re-attach click listener (not checkedChange to avoid recursion)
        binding.checkAll.setOnClickListener {
            val shouldSelect = binding.checkAll.isChecked
            if (shouldSelect) {
                for (app in filteredApps) allowedPackages.add(app.packageName)
            } else {
                for (app in filteredApps) allowedPackages.remove(app.packageName)
            }
            saveApps()
            appAdapter.notifyDataSetChanged()
            updateSelectAllCheckbox()
        }
    }

    private fun saveApps() {
        SecureStorage.saveAllowedApps(this, allowedPackages)
        updateCounter()
        updateTabBadges()
    }

    // ──────────── Sites page ────────────

    private fun setupSitesPage() {
        domainAdapter = DomainListAdapter()
        binding.recyclerDomains.layoutManager = LinearLayoutManager(this)
        binding.recyclerDomains.adapter = domainAdapter

        binding.btnAddDomain.setOnClickListener { addDomain() }

        binding.editDomain.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                addDomain()
                true
            } else false
        }

        // Domain exclusions require API 33 (Android 13) for addRoute(IpPrefix, excluded).
        // On older devices, saved domains are stored but not applied to VPN routing.
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
            binding.textDomainNote.visibility = android.view.View.VISIBLE
        } else {
            binding.textDomainNote.visibility = android.view.View.GONE
        }
    }

    private fun addDomain() {
        val raw = binding.editDomain.text.toString().trim()
            .lowercase()
            .removePrefix("http://")
            .removePrefix("https://")
            .removeSuffix("/")
            .trim()

        if (raw.isEmpty()) return

        // Validate domain format
        val domainRegex = Regex("^([a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?\\.)+[a-z]{2,}$")
        if (!domainRegex.matches(raw)) {
            Toast.makeText(this, getString(R.string.split_tunnel_domain_invalid), Toast.LENGTH_SHORT).show()
            return
        }

        if (excludedDomains.contains(raw)) {
            Toast.makeText(this, getString(R.string.split_tunnel_domain_exists), Toast.LENGTH_SHORT).show()
            return
        }

        excludedDomains.add(0, raw)
        saveDomains()
        domainAdapter.notifyDataSetChanged()
        binding.editDomain.text?.clear()
    }

    private fun saveDomains() {
        SecureStorage.saveExcludedDomains(this, excludedDomains)
        updateCounter()
        updateTabBadges()
    }

    // ──────────── Counter ────────────

    private fun updateCounter() {
        val appCount = allowedPackages.size
        val domainCount = excludedDomains.size
        binding.textCounter.text = when {
            appCount > 0 && domainCount > 0 -> getString(
                R.string.split_tunnel_hint_combined,
                getString(R.string.split_tunnel_hint_apps, appCount),
                getString(R.string.split_tunnel_hint_sites, domainCount)
            )
            appCount > 0 -> getString(R.string.split_tunnel_vpn_count, appCount)
            domainCount > 0 -> getString(R.string.split_tunnel_bypass_count, domainCount)
            else -> ""
        }
    }

    // ──────────── App adapter ────────────

    inner class AppListAdapter : RecyclerView.Adapter<AppListAdapter.VH>() {

        inner class VH(parent: ViewGroup) : RecyclerView.ViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false)
        ) {
            val icon: ImageView = itemView.findViewById(R.id.imgAppIcon)
            val name: TextView = itemView.findViewById(R.id.textAppName)
            val check: CheckBox = itemView.findViewById(R.id.checkExcluded)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(parent)
        override fun getItemCount() = filteredApps.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val app = filteredApps[position]
            holder.icon.setImageDrawable(app.icon)
            holder.name.text = app.name
            holder.check.setOnCheckedChangeListener(null)
            holder.check.isChecked = allowedPackages.contains(app.packageName)
            holder.check.setOnCheckedChangeListener { _, checked ->
                if (checked) allowedPackages.add(app.packageName)
                else allowedPackages.remove(app.packageName)
                saveApps()
                updateSelectAllCheckbox()
            }
            holder.itemView.setOnClickListener {
                holder.check.isChecked = !holder.check.isChecked
            }
        }
    }

    // ──────────── Domain adapter ────────────

    inner class DomainListAdapter : RecyclerView.Adapter<DomainListAdapter.VH>() {

        inner class VH(parent: ViewGroup) : RecyclerView.ViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_domain, parent, false)
        ) {
            val domain: TextView = itemView.findViewById(R.id.textDomain)
            val delete: ImageButton = itemView.findViewById(R.id.btnDelete)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(parent)
        override fun getItemCount() = excludedDomains.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val domain = excludedDomains[position]
            holder.domain.text = domain
            holder.delete.setOnClickListener {
                // Capture the domain value at bind time rather than reading adapterPosition
                // in the click handler. adapterPosition can return -1 or a stale index
                // while the RecyclerView is laying out (rapid taps, concurrent deletions),
                // causing IndexOutOfBoundsException on excludedDomains.removeAt().
                if (excludedDomains.remove(domain)) {
                    saveDomains()
                    notifyDataSetChanged()
                }
            }
        }
    }
}
