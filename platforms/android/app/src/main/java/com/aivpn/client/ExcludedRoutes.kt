package com.aivpn.client

import java.math.BigInteger
import java.net.InetAddress

data class IncludedRoute(val address: String, val prefix: Int)

internal fun boundedExcludedAddresses(addresses: Collection<InetAddress>): List<InetAddress> =
    listOf(4, 16).flatMap { size -> addresses.filter { it.address.size == size }.distinct().take(64) }

/** Дополнение к исключенным адресам для Android без Builder.excludeRoute. */
fun routesAroundExcludedAddresses(excluded: Collection<InetAddress>, bits: Int): List<IncludedRoute> {
    require(bits == 32 || bits == 128)
    val size = bits / 8
    val values = excluded.filter { it.address.size == size }.map { BigInteger(1, it.address) }.distinct()
    require(values.size <= 64) { "Too many excluded addresses" }
    val routes = mutableListOf<IncludedRoute>()
    fun visit(base: BigInteger, prefix: Int, remaining: List<BigInteger>) {
        if (remaining.isEmpty()) {
            // Не более bits * 64 маршрутов: число адресов ограничено выше.
            val raw = base.toByteArray().takeLast(size).toByteArray()
            val address = ByteArray(size)
            raw.copyInto(address, size - raw.size)
            routes.add(IncludedRoute(requireNotNull(InetAddress.getByAddress(address).hostAddress), prefix))
            return
        }
        if (prefix == bits) return
        val bit = bits - prefix - 1
        val (upper, lower) = remaining.partition { it.testBit(bit) }
        visit(base, prefix + 1, lower)
        visit(base.setBit(bit), prefix + 1, upper)
    }
    visit(BigInteger.ZERO, 0, values)
    return routes
}

/** DNS исключений не должен задерживать установку туннеля без ограничения. */
internal object DomainExclusionResolver {
    private val executor = java.util.concurrent.ThreadPoolExecutor(
        2, 2, 0L, java.util.concurrent.TimeUnit.MILLISECONDS,
        java.util.concurrent.ArrayBlockingQueue(64),
        { task -> Thread(task, "aivpn-domain-exclusions").apply { isDaemon = true } },
        java.util.concurrent.ThreadPoolExecutor.AbortPolicy(),
    )

    fun resolve(domains: List<String>, timeoutMs: Long = 5_000,
                lookup: (String) -> List<InetAddress>): List<InetAddress> {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeoutMs.coerceIn(0, 5_000))
        val pending = domains.distinct().take(64).mapNotNull { domain ->
            try {
                executor.submit<List<InetAddress>> {
                    if (System.nanoTime() >= deadline) emptyList() else try { lookup(domain) } catch (_: Exception) { emptyList() }
                }
            } catch (_: java.util.concurrent.RejectedExecutionException) { null }
        }
        val addresses = linkedMapOf<String, InetAddress>()
        try {
            for (future in pending) {
                try {
                    val remaining = (deadline - System.nanoTime()).coerceAtLeast(0)
                    val result = if (future.isDone) future.get() else future.get(remaining, java.util.concurrent.TimeUnit.NANOSECONDS)
                    for (address in result) addresses[address.hostAddress ?: ""] = address
                } catch (_: java.util.concurrent.TimeoutException) {
                } catch (_: java.util.concurrent.ExecutionException) {
                }
            }
        } finally {
            for (future in pending) if (!future.isDone) future.cancel(true)
            executor.purge()
        }
        return addresses.values.toList()
    }
}
