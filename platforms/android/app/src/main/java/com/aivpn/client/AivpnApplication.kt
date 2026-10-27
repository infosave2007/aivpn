package com.aivpn.client

import android.app.Application
import com.google.android.material.color.DynamicColors
import com.google.android.material.color.DynamicColorsOptions

class AivpnApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        UiAppearance.applyTheme(this)
        DynamicColors.applyToActivitiesIfAvailable(
            this,
            DynamicColorsOptions.Builder()
                .setPrecondition { activity, _ -> UiAppearance.dynamicColors(activity) }
                .build(),
        )
    }
}
