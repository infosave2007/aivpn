package com.aivpn.client

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ScreenLoaderTest {
    private data class Options(val client: String, val mask: String)

    @Test fun failedRefreshDropsThePreviousActionTarget() = runBlocking {
        val snapshot = ScreenSnapshot<Options>()
        val loader = ScreenLoader()
        snapshot.publish(Options("client-a", "mask-a")) { true }

        snapshot.invalidate()
        loader.load { /* Ошибка запроса не публикует новый снимок. */ }

        assertNull(snapshot.value)
        loader.load { current -> snapshot.publish(Options("client-b", "mask-b"), current) }
        assertEquals(Options("client-b", "mask-b"), snapshot.value)
    }

    @Test fun oldResponseCannotRestoreAnActionTargetAfterFailedRefresh() = runBlocking {
        val snapshot = ScreenSnapshot<Options>()
        val loader = ScreenLoader()
        val release = CompletableDeferred<Unit>()
        var requests = 0
        snapshot.publish(Options("client-before", "mask-before")) { true }
        val load: suspend (() -> Boolean) -> Unit = { current ->
            if (++requests == 1) {
                release.await()
                snapshot.publish(Options("client-old", "mask-old"), current)
            }
        }
        snapshot.invalidate()
        val first = launch(start = CoroutineStart.UNDISPATCHED) { loader.load(load) }
        snapshot.invalidate()
        loader.load(load)
        release.complete(Unit)
        first.join()

        assertEquals(2, requests)
        assertNull(snapshot.value)
    }

    @Test fun cancelledRefreshDoesNotRestoreThePreviousActionTarget() = runBlocking {
        val snapshot = ScreenSnapshot<Options>()
        val loader = ScreenLoader()
        val release = CompletableDeferred<Unit>()
        snapshot.publish(Options("client-a", "mask-a")) { true }
        snapshot.invalidate()
        val first = launch(start = CoroutineStart.UNDISPATCHED) {
            loader.load { current ->
                release.await()
                snapshot.publish(Options("client-old", "mask-old"), current)
            }
        }
        first.cancel()
        first.join()

        assertNull(snapshot.value)
        loader.load { current -> snapshot.publish(Options("client-new", "mask-new"), current) }
        assertEquals(Options("client-new", "mask-new"), snapshot.value)
    }

    @Test fun overlappingRefreshesCoalesceWithoutRenderingAnOldResponse() = runBlocking {
        val loader = ScreenLoader()
        val release = CompletableDeferred<Unit>()
        var requests = 0
        var active = 0
        var maximumActive = 0
        val rendered = mutableListOf<Int>()
        val load: suspend (() -> Boolean) -> Unit = { isCurrent ->
            val response = ++requests
            active++
            maximumActive = maxOf(maximumActive, active)
            if (response == 1) release.await()
            active--
            if (isCurrent()) rendered.add(response)
        }
        val initial = launch(start = CoroutineStart.UNDISPATCHED) { loader.load(load) }
        loader.load(load)
        loader.load(load)
        assertEquals(1, requests)
        release.complete(Unit)
        initial.join()
        assertEquals(2, requests)
        assertEquals(1, maximumActive)
        assertEquals(listOf(2), rendered)
    }

    @Test fun completedLoadAllowsNextRefresh() = runBlocking {
        val loader = ScreenLoader()
        var requests = 0
        repeat(2) { loader.load { requests++ } }
        assertEquals(2, requests)
    }

    @Test fun failedLoadReleasesTheScreenForRetry() = runBlocking {
        val loader = ScreenLoader()
        try {
            loader.load { throw IllegalStateException("Expected failure") }
            fail("Expected load failure")
        } catch (_: IllegalStateException) {
        }
        var rendered = false
        loader.load { rendered = true }
        assertTrue(rendered)
    }
}
