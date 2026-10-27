package com.aivpn.client

import android.content.Context
import android.graphics.Typeface
import android.util.AttributeSet
import android.util.TypedValue
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.content.res.AppCompatResources
import java.text.NumberFormat
import java.util.Locale
import kotlin.math.max

/** Счетчики остаются читаемыми при узком экране и увеличенном системном шрифте. */
class SessionStatsView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : ViewGroup(context, attrs) {
    private val received = metric(R.drawable.ic_vpn_download)
    private val elapsed = metric(R.drawable.ic_vpn_timer)
    private val sent = metric(R.drawable.ic_vpn_upload)
    private var rows = 1
    private var elapsedSeconds = 0L
    private val gap get() = dp(8)

    init {
        isClickable = true
        isFocusable = true
        minimumHeight = dp(48)
        val background = TypedValue()
        context.theme.resolveAttribute(android.R.attr.selectableItemBackground, background, true)
        setBackgroundResource(background.resourceId)
        setPadding(0, dp(8), 0, dp(8))
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_YES
        setElapsed(0)
        setTraffic(null, null)
    }

    private fun metric(icon: Int): TextView = TextView(context).apply {
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTextColor(UiAppearance.color(context, com.google.android.material.R.attr.colorOnSurfaceVariant))
        typeface = Typeface.create("sans-serif", Typeface.NORMAL)
        fontFeatureSettings = "tnum"
        includeFontPadding = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        val drawable = AppCompatResources.getDrawable(context, icon)?.mutate()?.apply {
            setBounds(0, 0, dp(14), dp(14))
            setTint(currentTextColor)
        }
        setCompoundDrawablesRelative(drawable, null, null, null)
        compoundDrawablePadding = dp(4)
        gravity = android.view.Gravity.CENTER
        addView(this)
    }

    fun setTraffic(bytesSent: Long?, bytesReceived: Long?) {
        sent.text = formatBytes(bytesSent)
        received.text = formatBytes(bytesReceived)
        updateDescription()
    }

    fun setElapsed(seconds: Long) {
        elapsedSeconds = seconds.coerceAtLeast(0)
        elapsed.text = String.format(Locale.getDefault(), "%02d:%02d:%02d", elapsedSeconds / 3600, elapsedSeconds % 3600 / 60, elapsedSeconds % 60)
        updateDescription()
    }

    private fun updateDescription() {
        contentDescription = context.getString(R.string.ui_session_accessibility, received.text, elapsed.text, sent.text)
    }

    fun elapsedText(): String = elapsed.text.toString()
    fun receivedText(): String = received.text.toString()
    fun sentText(): String = sent.text.toString()

    private fun formatBytes(bytes: Long?): String {
        if (bytes == null || bytes < 0) return context.getString(R.string.ui_no_data)
        val units = intArrayOf(R.string.ui_byte, R.string.ui_kilobyte, R.string.ui_megabyte, R.string.ui_gigabyte, R.string.ui_terabyte)
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024 && unit < units.lastIndex) { value /= 1024; unit++ }
        val number = NumberFormat.getNumberInstance(resources.configuration.locales[0]).apply {
            isGroupingUsed = false
            maximumFractionDigits = if (unit == 0) 0 else if (value < 10) 2 else 1
        }.format(value)
        return "$number\u00a0${context.getString(units[unit])}"
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val available = MeasureSpec.getSize(widthMeasureSpec) - paddingLeft - paddingRight
        for (child in listOf(received, elapsed, sent)) {
            child.measure(MeasureSpec.makeMeasureSpec(available.coerceAtLeast(0), MeasureSpec.AT_MOST), MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED))
        }
        val edgeWidth = max(received.measuredWidth, sent.measuredWidth)
        rows = when {
            edgeWidth * 2 + elapsed.measuredWidth + gap * 2 <= available -> 1
            received.measuredWidth + sent.measuredWidth + gap <= available -> 2
            else -> 3
        }
        val textHeight = max(elapsed.measuredHeight, max(received.measuredHeight, sent.measuredHeight))
        val height = max(minimumHeight, paddingTop + paddingBottom + textHeight * rows + gap * (rows - 1))
        setMeasuredDimension(MeasureSpec.getSize(widthMeasureSpec), resolveSize(height, heightMeasureSpec))
    }

    override fun onLayout(changed: Boolean, left: Int, top: Int, right: Int, bottom: Int) {
        val textHeight = max(elapsed.measuredHeight, max(received.measuredHeight, sent.measuredHeight))
        val innerWidth = width - paddingLeft - paddingRight
        fun place(view: TextView, x: Int, row: Int) {
            val y = if (rows == 1) (height - view.measuredHeight) / 2 else paddingTop + row * (textHeight + gap)
            view.layout(x, y, x + view.measuredWidth, y + view.measuredHeight)
        }
        fun center(view: TextView) = paddingLeft + (innerWidth - view.measuredWidth) / 2
        val start = if (layoutDirection == LAYOUT_DIRECTION_RTL) sent else received
        val end = if (layoutDirection == LAYOUT_DIRECTION_RTL) received else sent
        if (rows == 3) {
            place(elapsed, center(elapsed), 0)
            place(received, center(received), 1)
            place(sent, center(sent), 2)
        } else {
            place(elapsed, center(elapsed), 0)
            place(start, paddingLeft, rows - 1)
            place(end, width - paddingRight - end.measuredWidth, rows - 1)
        }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
