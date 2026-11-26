package com.aivpn.client

import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/**
 * Lays the activity out edge to edge and keeps [root]'s content clear of the
 * status bar, navigation bar, display cutout and on-screen keyboard.
 *
 * Android 15 and later always draw apps that target API 35+ behind the system
 * bars, and Android 16 ignores the opt-out, so every screen applies the insets
 * itself. Calling [enableEdgeToEdge] on all versions gives the same layout and
 * bar icon contrast on older devices. The keyboard inset replaces the resize
 * that `adjustResize` no longer performs once the app handles insets.
 *
 * Call it right after `setContentView`. The root keeps its own padding and the
 * insets are added on top; they are consumed so child views do not add them
 * a second time.
 */
fun ComponentActivity.applySystemBarInsets(root: View) {
    enableEdgeToEdge()
    val left = root.paddingLeft
    val top = root.paddingTop
    val right = root.paddingRight
    val bottom = root.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
        val bars = insets.getInsets(
            WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
        )
        val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
        view.setPadding(
            left + bars.left,
            top + bars.top,
            right + bars.right,
            bottom + maxOf(bars.bottom, keyboard.bottom),
        )
        WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(root)
}
