package com.aivpn.client

import android.content.Context
import android.os.Build
import android.util.TypedValue
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch

object UiAppearance {
    private fun preferences(context: Context) =
        context.createDeviceProtectedStorageContext().getSharedPreferences("aivpn_appearance", Context.MODE_PRIVATE)

    fun color(context: Context, attr: Int): Int {
        val value = TypedValue()
        check(context.theme.resolveAttribute(attr, value, true)) { "Missing theme color: $attr" }
        return if (value.resourceId != 0) context.getColor(value.resourceId) else value.data
    }

    fun dynamicColors(context: Context): Boolean = preferences(context).getBoolean("dynamic_colors", false)

    fun applyTheme(context: Context) {
        AppCompatDelegate.setDefaultNightMode(preferences(context).getInt("theme", AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM))
    }

    fun themeSummary(context: Context): String = context.getString(
        when (preferences(context).getInt("theme", AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)) {
            AppCompatDelegate.MODE_NIGHT_NO -> R.string.ui_theme_light
            AppCompatDelegate.MODE_NIGHT_YES -> R.string.ui_theme_dark
            else -> R.string.ui_theme_system
        },
    )

    fun showThemeDialog(activity: AppCompatActivity) {
        val modes = intArrayOf(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM, AppCompatDelegate.MODE_NIGHT_NO, AppCompatDelegate.MODE_NIGHT_YES)
        val labels = arrayOf(R.string.ui_theme_system, R.string.ui_theme_light, R.string.ui_theme_dark).map(activity::getString).toTypedArray()
        val prefs = preferences(activity)
        var selected = modes.indexOf(prefs.getInt("theme", modes[0])).coerceAtLeast(0)
        val dynamic = MaterialSwitch(activity).apply {
            text = activity.getString(R.string.ui_dynamic_colors)
            isChecked = dynamicColors(activity)
            isEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
            minHeight = (56 * resources.displayMetrics.density).toInt()
            setPadding((24 * resources.displayMetrics.density).toInt(), 0, (24 * resources.displayMetrics.density).toInt(), 0)
            contentDescription = activity.getString(R.string.ui_dynamic_colors_detail)
        }
        val container = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL; addView(dynamic) }
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.ui_appearance)
            .setSingleChoiceItems(labels, selected) { _, which -> selected = which }
            .setView(container)
            .setPositiveButton(R.string.btn_save) { _, _ ->
                val oldMode = prefs.getInt("theme", modes[0])
                val changedColors = dynamic.isChecked != dynamicColors(activity)
                prefs.edit().putInt("theme", modes[selected]).putBoolean("dynamic_colors", dynamic.isChecked).apply()
                applyTheme(activity)
                if (oldMode == modes[selected] || changedColors) activity.recreate()
            }
            .setNegativeButton(R.string.btn_cancel, null)
            .show()
    }
}
