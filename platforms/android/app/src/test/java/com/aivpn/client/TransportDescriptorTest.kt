package com.aivpn.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract test for the settings descriptor.
 *
 * The compiler does not check this contract — a drift produces no build error,
 * just a section rendered wrongly or skipped in silence. The reference below is
 * the same document the Rust side parses in
 * `crates/aivpn-common/tests/ui_ext_descriptor.rs`; when the two disagree, both
 * suites must fail, not one.
 */
class TransportDescriptorTest {

    private val reference = """
        {
          "schema": 1,
          "id": "alt",
          "title": "Extra transport",
          "transport": "alt",
          "gate_field": "enabled",
          "fields": [
            { "key": "enabled",  "label": "Enable",   "type": "toggle" },
            { "key": "endpoint", "label": "Endpoint", "type": "text" },
            { "key": "secret",   "label": "Secret",   "type": "secret" },
            { "key": "mode",     "label": "Mode",     "type": "select",
              "options": ["a", "b", "c"] }
          ]
        }
    """.trimIndent()

    @Test
    fun referenceDescriptorParses() {
        val d = parseTransportDescriptor(reference)
        assertEquals("alt", d.id)
        assertEquals("alt", d.transport)
        assertEquals("enabled", d.gateField)
        assertEquals(4, d.fields.size)
        assertTrue(d.fields[0].kind is FieldKind.Toggle)
        assertTrue(d.fields[1].kind is FieldKind.Text)
        assertTrue(d.fields[2].kind is FieldKind.Secret)
        assertEquals(listOf("a", "b", "c"), (d.fields[3].kind as FieldKind.Select).options)
    }

    @Test
    fun unknownSchemaVersionIsRejectedLoudly() {
        val bad = reference.replace("\"schema\": 1", "\"schema\": 2")
        val e = runCatching { parseTransportDescriptor(bad) }.exceptionOrNull()
        assertTrue("expected a DescriptorException, got $e", e is DescriptorException)
        assertTrue("error must name the schema: ${e?.message}", e!!.message!!.contains("schema"))
    }

    @Test
    fun unknownFieldTypeIsAParseErrorNotASkip() {
        val bad = reference.replace("\"type\": \"toggle\"", "\"type\": \"slider\"")
        assertTrue(runCatching { parseTransportDescriptor(bad) }.isFailure)
    }

    @Test
    fun gateFieldOffMeansDefaultTransport() {
        val d = parseTransportDescriptor(reference)
        val values = mapOf<String, FieldValue>(
            "enabled" to FieldValue.Toggle(false),
            "endpoint" to FieldValue.Text("host:1"),
        )
        assertNull(d.apply(values))
    }

    @Test
    fun gateFieldOnYieldsChoiceWithAllValues() {
        val d = parseTransportDescriptor(reference)
        val values = linkedMapOf<String, FieldValue>(
            "enabled" to FieldValue.Toggle(true),
            "endpoint" to FieldValue.Text("host:1"),
            "secret" to FieldValue.Text("s3cr3t"),
            "mode" to FieldValue.Select(2),
        )
        val choice = d.apply(values)!!
        assertEquals("alt", choice.name)
        val params = org.json.JSONObject(choice.paramsJson)
        assertEquals("host:1", params.getString("endpoint"))
        assertEquals("s3cr3t", params.getString("secret"))
        assertEquals(2, params.getInt("mode"))
        assertTrue(
            "the gate field is the host's decision, not a transport parameter",
            !params.has("enabled")
        )
    }

    @Test
    fun initialValuesCoverEveryDeclaredField() {
        val d = parseTransportDescriptor(reference)
        val initial = d.initialValues()
        assertEquals(d.fields.map { it.key }.toSet(), initial.keys)
    }
}
