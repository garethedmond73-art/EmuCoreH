package com.sbro.emucoreh.data.drive

import android.accounts.Account
import android.app.Activity
import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import com.google.android.gms.auth.api.identity.AuthorizationRequest
import com.google.android.gms.auth.api.identity.AuthorizationResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.common.api.Scope
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.tasks.Task
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

object DriveAuthorization {
    const val SCOPE = "https://www.googleapis.com/auth/drive.file"

    suspend fun chooseAccount(activity: Activity): String {
        // The Google Services plugin generates this resource only when a Firebase
        // configuration is present. Report a configuration error when it is absent.
        val clientIdResourceId = activity.resources.getIdentifier(
            "default_web_client_id", "string", activity.packageName
        )
        if (clientIdResourceId == 0) throw DriveBackupException("configuration")
        val clientId = activity.getString(clientIdResourceId)
        if (clientId.isBlank()) throw DriveBackupException("configuration")
        val request = GetCredentialRequest.Builder().addCredentialOption(
            GetSignInWithGoogleOption.Builder(clientId).build()
        ).build()
        val result = CredentialManager.create(activity).getCredential(activity, request)
        return GoogleIdTokenCredential.createFrom(result.credential.data).id
    }

    suspend fun authorize(context: Context, email: String): AuthorizationResult =
        Identity.getAuthorizationClient(context).authorize(
            AuthorizationRequest.builder().setAccount(Account(email, "com.google"))
                .setRequestedScopes(listOf(Scope(SCOPE))).build()
        ).awaitDrive()

    suspend fun token(context: Context, email: String): String {
        val result = try { authorize(context, email) }
        catch (error: ApiException) { throw DriveBackupException(if (error.statusCode == 7) "network" else "auth", error) }
        if (result.hasResolution()) throw DriveBackupException("auth")
        return result.accessToken ?: throw DriveBackupException("auth")
    }
}

internal suspend fun <T> Task<T>.awaitDrive(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { if (continuation.isActive) continuation.resume(it) }
    addOnFailureListener { if (continuation.isActive) continuation.resumeWithException(it) }
    addOnCanceledListener { continuation.cancel() }
}
