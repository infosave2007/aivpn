package com.aivpn.client

import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout

/**
 * Generic renderer for the descriptor returned by [loadTransportDescriptor].
 *
 * Knows nothing about what the fields mean: [FieldKind.Toggle] becomes a
 * CheckBox, [FieldKind.Text]/[FieldKind.Secret] an EditText (password input for
 * the latter), [FieldKind.Select] a Spinner. "Применить" folds the edited
 * values back through [TransportDescriptor.apply] and persists the resulting
 * [TransportChoice] — or clears it when null — under
 * [PrefsKeys.PREF_EXT_TRANSPORT_NAME] / [PrefsKeys.PREF_EXT_TRANSPORT_PARAMS],
 * which [AivpnService] forwards into the native core on the next connect.
 *
 * Field values are persisted generically (per descriptor id + field key) so the
 * screen re-opens with what the user last entered.
 *
 * In the public build there is no descriptor asset: the entry point in
 * [MainActivity] is hidden and this Activity finishes immediately if it is
 * somehow launched anyway.
 */
class TransportSettingsActivity : AppCompatActivity() {

    /** Live editor views for one rendered field, read back on apply. */
    private sealed class FieldEditor {
        class ToggleEditor(val check: CheckBox) : FieldEditor()
        class TextEditor(val edit: EditText) : FieldEditor()
        class SelectEditor(val spinner: Spinner, val options: List<String>) : FieldEditor()
    }

    private val editors = mutableListOf<Pair<SettingsField, FieldEditor>>()
    private var descriptor: TransportDescriptor? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val desc = loadTransportDescriptor(this)
        if (desc == null) {
            // Public build: nothing to configure — never show an empty screen.
            finish()
            return
        }
        descriptor = desc

        val prefs = try {
            SecureStorage.transportPreferences(this)
        } catch (_: Exception) {
            Toast.makeText(this, getString(R.string.status_storage_unavailable), Toast.LENGTH_LONG).show()
            finish()
            return
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colorAttr(com.google.android.material.R.attr.colorSurface, R.color.background))
        }
        val toolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            minimumHeight = 64.dp
            setPadding(4.dp, 4.dp, 16.dp, 4.dp)
        }
        toolbar.addView(ImageButton(this).apply {
            setImageResource(R.drawable.ic_vpn_back)
            scaleType = ImageView.ScaleType.CENTER_INSIDE
            contentDescription = getString(R.string.ui_back)
            setColorFilter(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
            val typed = android.util.TypedValue()
            if (theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, typed, true) &&
                typed.resourceId != 0
            ) {
                setBackgroundResource(typed.resourceId)
            }
            layoutParams = LinearLayout.LayoutParams(48.dp, 48.dp)
            setOnClickListener { finish() }
        })
        toolbar.addView(TextView(this).apply {
            text = getString(R.string.transport_settings_title)
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleLarge)
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
            maxLines = 2
            ellipsize = android.text.TextUtils.TruncateAt.END
            setPadding(4.dp, 0, 0, 0)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        root.addView(toolbar)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20.dp, 8.dp, 20.dp, 24.dp)
        }

        // The section heading comes from the descriptor, never from this
        // build's own strings: an edition the module is not part of must
        // contribute none of its text.
        container.addView(TextView(this).apply {
            text = desc.title
            textSize = 16f
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
            setPadding(0, 8.dp, 0, 4.dp)
        })

        for (field in desc.fields) {
            renderField(container, prefs, desc.id, field)
        }

        container.addView(MaterialButton(this).apply {
            text = getString(R.string.transport_apply)
            textSize = 14f
            isAllCaps = false
            insetTop = 0
            insetBottom = 0
            minHeight = 48.dp
            setOnClickListener { applyAll() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 16.dp, 0, 0) }
        })

        root.addView(ScrollView(this).apply {
            isFillViewport = true
            addView(container)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f,
            )
        })
        setContentView(root)
    }

    // ──────────── Rendering ────────────

    private fun renderField(
        container: LinearLayout,
        prefs: android.content.SharedPreferences,
        descriptorId: String,
        field: SettingsField,
    ) {
        val prefKey = fieldPrefKey(descriptorId, field.key)
        when (val kind = field.kind) {
            is FieldKind.Toggle -> {
                val check = MaterialCheckBox(this).apply {
                    text = field.label
                    textSize = 16f
                    minHeight = 48.dp
                    setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
                    isChecked = prefs.getBoolean(prefKey, false)
                }
                container.addView(check)
                editors.add(field to FieldEditor.ToggleEditor(check))
            }
            is FieldKind.Text, is FieldKind.Secret -> {
                val secret = kind is FieldKind.Secret
                val edit = TextInputEditText(this).apply {
                    inputType = if (secret) {
                        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    } else {
                        InputType.TYPE_CLASS_TEXT
                    }
                    setText(prefs.getString(prefKey, "") ?: "")
                    setSingleLine(true)
                    textSize = 16f
                    importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                }
                val box = TextInputLayout(
                    this,
                    null,
                    com.google.android.material.R.attr.textInputOutlinedStyle,
                ).apply {
                    hint = field.label
                    addView(
                        edit,
                        LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT,
                        ),
                    )
                }
                container.addView(
                    box,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = 8.dp },
                )
                editors.add(field to FieldEditor.TextEditor(edit))
            }
            is FieldKind.Select -> {
                container.addView(labelView(field.label))
                val spinner = Spinner(this).apply {
                    minimumHeight = 48.dp
                    adapter = object : ArrayAdapter<String>(
                        this@TransportSettingsActivity,
                        android.R.layout.simple_spinner_item,
                        kind.options,
                    ) {
                        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                            return styleSpinnerText(super.getView(position, convertView, parent))
                        }

                        override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View {
                            return styleSpinnerText(super.getDropDownView(position, convertView, parent))
                        }
                    }.also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
                    if (kind.options.isNotEmpty()) {
                        val stored = prefs.getInt(prefKey, 0)
                        setSelection(stored.coerceIn(0, kind.options.size - 1))
                    }
                }
                container.addView(spinner)
                editors.add(field to FieldEditor.SelectEditor(spinner, kind.options))
            }
        }
    }

    private fun labelView(label: String): TextView = TextView(this).apply {
        text = label
        textSize = 14f
        setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurfaceVariant, R.color.text_secondary))
        setPadding(0, 12.dp, 0, 2.dp)
    }

    private fun styleSpinnerText(view: View): View {
        (view as? TextView)?.apply {
            textSize = 16f
            minHeight = 48.dp
            setTextColor(colorAttr(com.google.android.material.R.attr.colorOnSurface, R.color.text_primary))
        }
        return view
    }

    private fun colorAttr(attr: Int, fallback: Int): Int {
        val typed = android.util.TypedValue()
        return if (theme.resolveAttribute(attr, typed, true)) {
            if (typed.resourceId != 0) getColor(typed.resourceId) else typed.data
        } else {
            getColor(fallback)
        }
    }

    // ──────────── Apply ────────────

    private fun applyAll() {
        val desc = descriptor ?: return
        val prefs = try {
            SecureStorage.transportPreferences(this)
        } catch (_: Exception) {
            Toast.makeText(this, getString(R.string.status_storage_unavailable), Toast.LENGTH_LONG).show()
            return
        }
        val editor = prefs.edit()

        // Read every rendered field back, persisting the raw state generically
        // so the screen restores it next time.
        val values = LinkedHashMap<String, FieldValue>()
        for ((field, fieldEditor) in editors) {
            val prefKey = fieldPrefKey(desc.id, field.key)
            values[field.key] = when (fieldEditor) {
                is FieldEditor.ToggleEditor -> {
                    val on = fieldEditor.check.isChecked
                    editor.putBoolean(prefKey, on)
                    FieldValue.Toggle(on)
                }
                is FieldEditor.TextEditor -> {
                    val text = fieldEditor.edit.text.toString()
                    editor.putString(prefKey, text)
                    FieldValue.Text(text)
                }
                is FieldEditor.SelectEditor -> {
                    val selected = if (fieldEditor.options.isEmpty()) {
                        0
                    } else {
                        fieldEditor.spinner.selectedItemPosition
                            .coerceIn(0, fieldEditor.options.size - 1)
                    }
                    editor.putInt(prefKey, selected)
                    FieldValue.Select(selected)
                }
            }
        }

        val choice = desc.apply(values)
        if (choice != null) {
            editor.putString(PrefsKeys.PREF_EXT_TRANSPORT_NAME, choice.name)
            editor.putString(PrefsKeys.PREF_EXT_TRANSPORT_PARAMS, choice.paramsJson)
        } else {
            editor.remove(PrefsKeys.PREF_EXT_TRANSPORT_NAME)
            editor.remove(PrefsKeys.PREF_EXT_TRANSPORT_PARAMS)
        }
        if (!editor.commit()) {
            Toast.makeText(this, getString(R.string.status_storage_unavailable), Toast.LENGTH_LONG).show()
            return
        }

        Toast.makeText(this, getString(R.string.transport_applied), Toast.LENGTH_SHORT).show()
        finish()
    }

    /** Generic per-field persistence key, namespaced per descriptor. */
    private fun fieldPrefKey(descriptorId: String, fieldKey: String): String =
        "ext_field_${descriptorId}_$fieldKey"

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
