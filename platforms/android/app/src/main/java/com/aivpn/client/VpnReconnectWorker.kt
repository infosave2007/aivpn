package com.aivpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * One-shot expedited watchdog: re-sends ACTION_CONNECT after the VPN service died
 * while the user still wanted it up ([PrefsKeys.PREF_VPN_DESIRED]). Scheduled from
 * AivpnService.onDestroy() on any non-manual teardown.
 *
 * Why this exists: START_STICKY covers a process KILL (the OS restarts the service
 * with a null intent, handled in onStartCommand), but a system-initiated service
 * STOP — Android 12+ battery "Restricted" state, OEM power managers (MIUI/Samsung
 * "sleeping apps"), the Android 13 Task-Manager "Stop" button — is never restarted
 * by the framework. Without this worker such a stop silently left traffic on the
 * real interface with the real IP until the user noticed.
 */
class VpnReconnectWorker(context: Context, params: WorkerParameters) :
    Worker(context, params) {

    override fun doWork(): Result {
        val ctx = applicationContext
        if (!BootPrefs.prefs(ctx).getBoolean(PrefsKeys.PREF_VPN_DESIRED, false)) {
            // The user disconnected manually in the meantime — nothing to heal.
            return Result.success()
        }
        if (AivpnService.isServiceActive) {
            return Result.success() // already back up (user or always-on beat us to it)
        }
        if (VpnService.prepare(ctx) != null) {
            // VPN permission revoked — consent can only be re-granted from an
            // Activity; the security-alert notification already points the user there.
            Log.w(TAG, "VPN permission revoked — cannot auto-reconnect from background")
            return Result.failure()
        }
        val profileId = resolveProfileId(ctx)
        if (profileId == null) {
            Log.w(TAG, "No profile available — cannot auto-reconnect")
            return Result.failure()
        }
        val intent = Intent(ctx, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("profile_id", profileId)
        }
        return try {
            ctx.startForegroundService(intent)
            Log.i(TAG, "Auto-reconnect dispatched for profile=$profileId")
            Result.success()
        } catch (e: Exception) {
            // ForegroundServiceStartNotAllowedException (API 31+) or similar —
            // retry with backoff; a later attempt may run with FGS-launch quota.
            Log.w(TAG, "startForegroundService failed: ${e.message}")
            Result.retry()
        }
    }

    /**
     * Same resolution order as BootReceiver / AivpnService.lastKnownProfileId():
     * securely-stored active ID → device-protected last-connected ID → first profile,
     * each candidate validated against the actual profile list.
     */
    private fun resolveProfileId(ctx: Context): String? {
        val lastId = BootPrefs.prefs(ctx).getString(PrefsKeys.PREF_LAST_PROFILE_ID, null)
            ?.takeIf { it.isNotBlank() }
        val profiles = try {
            SecureStorage.loadProfiles(ctx)
        } catch (e: Exception) {
            Log.w(TAG, "Secure storage unavailable while resolving profile: ${e.message}")
            return lastId
        }
        val activeId = try {
            SecureStorage.loadActiveProfileId(ctx).takeIf { it.isNotBlank() }
        } catch (e: Exception) { null }
        return when {
            activeId != null && profiles.any { it.id == activeId } -> activeId
            lastId != null && profiles.any { it.id == lastId }     -> lastId
            else                                                    -> profiles.firstOrNull()?.id
        }
    }

    /**
     * Required for expedited work on API < 31, where WorkManager runs the request
     * as a short foreground service and asks for this notification.
     */
    override fun getForegroundInfo(): ForegroundInfo {
        val ctx = applicationContext
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                ctx.getString(R.string.notification_reconnect_channel),
                NotificationManager.IMPORTANCE_LOW
            )
        )
        val notification = Notification.Builder(ctx, CHANNEL_ID)
            .setContentTitle(ctx.getString(R.string.app_name))
            .setContentText(ctx.getString(R.string.status_reconnecting))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        return ForegroundInfo(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val TAG = "VpnReconnectWorker"
        private const val UNIQUE_NAME = "aivpn_reconnect"
        /**
         * L1: the worker's OWN channel. It previously reused AivpnService's
         * "aivpn_events" id but created it with IMPORTANCE_LOW — and Android
         * keeps the LOWEST importance a channel was ever created with, so one
         * expedited-work run on API < 31 permanently silenced every future
         * connect/disconnect event notification. A quiet LOW-importance channel
         * is exactly right for this progress stub, so it gets a dedicated id.
         */
        private const val CHANNEL_ID = "aivpn_reconnect"
        private const val NOTIFICATION_ID = 4

        /** Enqueue (replacing any pending instance) an expedited reconnect attempt. */
        fun schedule(context: Context) {
            val request = OneTimeWorkRequestBuilder<VpnReconnectWorker>()
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .build()
            try {
                WorkManager.getInstance(context)
                    .enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.REPLACE, request)
                Log.i(TAG, "Reconnect work scheduled")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to schedule reconnect work: ${e.message}", e)
            }
        }
    }
}
