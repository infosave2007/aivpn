package com.aivpn.client

import android.content.Context
import org.json.JSONObject

/**
 * Descriptor-driven settings seam for pluggable transport configuration.
 *
 * A build that carries an alternative datagram transport ships a descriptor in
 * `assets/ext-sections.json`; it lists the fields to show, with their types and
 * labels. The host activity renders those fields generically, knowing nothing
 * about what any of them mean, and folds the edited values back into an opaque
 * transport selection ([TransportChoice] = name + JSON parameters) passed
 * through to the native core on the next connect.
 *
 * The public build ships no such asset, so [loadDescriptor] returns null, the
 * menu entry is hidden and the screen does not exist.
 *
 * # Why a descriptor and not a provider interface
 *
 * A provider would carry no logic: read the fields, check one switch, put the
 * rest into JSON. That does not need a class, a registry and a product flavor —
 * it needs a file. Keeping it as data means the public source tree is the same
 * tree an extended build compiles; only the APK's assets differ.
 *
 * # This contract is not checked by the compiler
 *
 * Unlike the Rust seam, a drift here produces no build error — just a section
 * rendered wrongly or skipped in silence. Hence the schema version, and hence
 * an unknown version or an unknown field type being a hard parse failure
 * rather than something to skip over.
 */

/** The only descriptor schema version this build understands. */
const val TRANSPORT_SCHEMA_VERSION = 1

/** Asset path a descriptor is read from. */
const val TRANSPORT_DESCRIPTOR_ASSET = "ext-sections.json"

/** Field type; the host picks a widget by this and nothing else. */
sealed class FieldKind {
    /** Rendered as a CheckBox. */
    object Toggle : FieldKind()

    /** Rendered as a single-line input. */
    object Text : FieldKind()

    /** Rendered as a password input. */
    object Secret : FieldKind()

    /** Rendered as a Spinner; the value is an index into [options]. */
    data class Select(val options: List<String>) : FieldKind()
}

/** One field of a section. [key] is opaque to the host; [label] is user-facing. */
data class SettingsField(
    val key: String,
    val label: String,
    val kind: FieldKind,
)

/** An edited value. */
sealed class FieldValue {
    data class Toggle(val on: Boolean) : FieldValue()
    data class Text(val value: String) : FieldValue()
    data class Select(val index: Int) : FieldValue()
}

/**
 * An opaque transport selection: a short [name] the native core understands
 * plus a JSON object of parameters. The host never inspects either.
 */
data class TransportChoice(
    val name: String,
    val paramsJson: String,
)

/** A parsed descriptor: one section of settings. */
data class TransportDescriptor(
    val id: String,
    val title: String,
    /** Transport name that goes into [TransportChoice]. */
    val transport: String,
    /**
     * Gate field: when it is off, [apply] yields null — "no override, use the
     * built-in default transport". Null means the section is always on.
     */
    val gateField: String?,
    val fields: List<SettingsField>,
) {
    /**
     * Fold edited [values] into a transport selection, or null when the gate
     * field is off.
     *
     * The gate field itself never reaches the parameters: it is the host's
     * decision about whether to use a transport at all, not a parameter of one.
     */
    fun apply(values: Map<String, FieldValue>): TransportChoice? {
        gateField?.let { gate ->
            val open = (values[gate] as? FieldValue.Toggle)?.on ?: false
            if (!open) return null
        }
        val params = JSONObject()
        for ((key, value) in values) {
            if (key == gateField) continue
            when (value) {
                is FieldValue.Toggle -> params.put(key, value.on)
                is FieldValue.Text -> params.put(key, value.value)
                is FieldValue.Select -> params.put(key, value.index)
            }
        }
        return TransportChoice(name = transport, paramsJson = params.toString())
    }

    /** Initial values for every declared field. */
    fun initialValues(): MutableMap<String, FieldValue> {
        val out = LinkedHashMap<String, FieldValue>()
        for (f in fields) {
            out[f.key] = when (f.kind) {
                is FieldKind.Toggle -> FieldValue.Toggle(false)
                is FieldKind.Text, is FieldKind.Secret -> FieldValue.Text("")
                is FieldKind.Select -> FieldValue.Select(0)
            }
        }
        return out
    }
}

/** Thrown when a descriptor is present but cannot be honoured. */
class DescriptorException(message: String) : Exception(message)

/** Parse a descriptor from JSON text. Throws [DescriptorException] on any drift. */
fun parseTransportDescriptor(text: String): TransportDescriptor {
    val root = try {
        JSONObject(text)
    } catch (e: Exception) {
        throw DescriptorException("descriptor is not valid JSON: ${e.message}")
    }

    val schema = root.optInt("schema", -1)
    if (schema != TRANSPORT_SCHEMA_VERSION) {
        throw DescriptorException(
            "unsupported descriptor schema $schema, this build understands $TRANSPORT_SCHEMA_VERSION"
        )
    }

    val rawFields = root.optJSONArray("fields")
        ?: throw DescriptorException("descriptor has no 'fields' array")
    val fields = ArrayList<SettingsField>(rawFields.length())
    for (i in 0 until rawFields.length()) {
        val f = rawFields.getJSONObject(i)
        val key = f.optString("key").ifEmpty { throw DescriptorException("field $i has no key") }
        val label = f.optString("label")
        val kind = when (val type = f.optString("type")) {
            "toggle" -> FieldKind.Toggle
            "text" -> FieldKind.Text
            "secret" -> FieldKind.Secret
            "select" -> {
                val opts = f.optJSONArray("options")
                val list = ArrayList<String>(opts?.length() ?: 0)
                for (j in 0 until (opts?.length() ?: 0)) list.add(opts!!.getString(j))
                FieldKind.Select(list)
            }
            else -> throw DescriptorException("unknown field type '$type' for key '$key'")
        }
        fields.add(SettingsField(key, label, kind))
    }

    return TransportDescriptor(
        id = root.optString("id"),
        title = root.optString("title"),
        transport = root.optString("transport"),
        gateField = if (root.has("gate_field")) root.getString("gate_field") else null,
        fields = fields,
    )
}

/**
 * Read the descriptor from assets, or null when this build ships none.
 *
 * A malformed descriptor is also null: a broken asset must not make the app
 * unusable. It is logged so the failure is findable.
 */
fun loadTransportDescriptor(context: Context): TransportDescriptor? = try {
    context.assets.open(TRANSPORT_DESCRIPTOR_ASSET).bufferedReader().use {
        parseTransportDescriptor(it.readText())
    }
} catch (e: java.io.FileNotFoundException) {
    null
} catch (e: Exception) {
    android.util.Log.w("TransportSettings", "descriptor ignored: ${e.message}")
    null
}
