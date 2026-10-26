package com.aivpn.client

/** Объединяет обновления одного экрана. Вызывать из основного потока. */
class ScreenLoader {
    private var loading = false
    private var requested = 0L

    suspend fun load(block: suspend (isCurrent: () -> Boolean) -> Unit) {
        requested++
        if (loading) return
        loading = true
        try {
            do {
                val current = requested
                block { current == requested }
            } while (current != requested)
        } finally {
            loading = false
        }
    }
}

/** Хранит актуальный снимок для действий экрана. Вызывать из основного потока. */
class ScreenSnapshot<T> {
    var value: T? = null
        private set

    fun invalidate() {
        value = null
    }

    fun publish(value: T, isCurrent: () -> Boolean): Boolean {
        if (!isCurrent()) return false
        this.value = value
        return true
    }
}

data class PoolSnapshot(val nodes: MgmtResult, val health: MgmtResult?)

suspend fun loadPoolSnapshot(
    nodes: suspend () -> MgmtResult,
    health: suspend () -> MgmtResult,
    isCurrent: () -> Boolean,
): PoolSnapshot {
    val nodesResult = nodes()
    val healthResult = if (nodesResult.ok && nodesResult.bodyArray() != null && isCurrent()) health() else null
    return PoolSnapshot(nodesResult, healthResult)
}
