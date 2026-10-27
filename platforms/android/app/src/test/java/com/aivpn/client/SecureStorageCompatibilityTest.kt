package com.aivpn.client

import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException

class SecureStorageCompatibilityTest {
    @Test
    fun recoveryDoesNotRequireTheAndroid33ExceptionClass() {
        val parent = javaClass.classLoader!!
        val name = "com.aivpn.client.SecureStorage"
        val loader = object : ClassLoader(parent) {
            override fun loadClass(className: String, resolve: Boolean): Class<*> {
                if (className == "android.security.KeyStoreException") throw ClassNotFoundException(className)
                if (className != name && !className.startsWith(name + "\$")) return super.loadClass(className, resolve)
                synchronized(this) {
                    findLoadedClass(className)?.let { return it }
                    val bytes = parent.getResourceAsStream(className.replace('.', '/') + ".class")!!.use { it.readBytes() }
                    return defineClass(className, bytes, 0, bytes.size).also { if (resolve) resolveClass(it) }
                }
            }
        }
        val storage = loader.loadClass(name)
        val instance = storage.getField("INSTANCE").get(null)
        val classify = storage.getDeclaredMethod("isCorruption", Throwable::class.java).apply { isAccessible = true }
        assertEquals(false, classify.invoke(instance, GeneralSecurityException("temporary")))
        assertEquals(true, classify.invoke(instance, AEADBadTagException("invalid ciphertext")))
        assertEquals(true, classify.invoke(instance, RuntimeException(AEADBadTagException("invalid ciphertext"))))
    }
}
