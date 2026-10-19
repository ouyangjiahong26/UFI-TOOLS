package com.minikano.f50_sms.modules.auth

import android.content.Context
import com.minikano.f50_sms.utils.KanoLog
import com.minikano.f50_sms.utils.KanoUtils
import com.minikano.f50_sms.utils.KanoUtils.Companion.normalizeLeadingSlashes
import com.minikano.f50_sms.utils.KanoUtils.Companion.normalizePath
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.queryString
import java.security.SecureRandom
import kotlin.math.abs

object KanoAuth {
    val PREFS_NAME = "kano_ZTE_store"
    val PREF_LOGIN_TOKEN = "login_token"
    val PREF_TOKEN_ENABLED = "login_token_enabled"
    val PREF_SIGN_KEY = "sign_key"

    // 签名时间戳与服务端允许的偏差，超出按过期拒绝，防止抓包后的无限期重放
    private const val SIGN_TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000L

    val apiWhiteListExact: Set<String> = setOf(
            "/api/get_custom_head",
            "/api/version_info",
            "/api/need_token",
            "/api/get_theme",
            "/api/SELinux",
            "/api/get_sign_key"
        )

    val apiWhiteListPrefix: List<String> = listOf(
        "/api/uploads"
    )

    // 签名密钥按设备随机生成。固定密钥写在源码里等于公开，任何人都能为任意设备伪造签名
    fun getOrCreateSignKey(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val stored = prefs.getString(PREF_SIGN_KEY, "") ?: ""
        if (stored.isNotBlank()) return stored

        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val key = KanoUtils.encodeHex(bytes)
        prefs.edit().putString(PREF_SIGN_KEY, key).apply()
        return key
    }

    fun checkAuth(call: ApplicationCall, context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val tokenStored = prefs.getString(PREF_LOGIN_TOKEN, "") ?: ""
        val tokenEnabled = prefs.getString(PREF_TOKEN_ENABLED, "true")?.toBoolean() ?: true

        val rawPath = call.request.path()
        val method = call.request.httpMethod.value

        val uri = normalizePath(rawPath)
        val uriForAuth = uri
        val rawPathForSign = normalizeLeadingSlashes(rawPath)
        KanoLog.d("UFI_TOOLS_LOG_KanoAuth") {
            "uri:$uri\t rawPath:$rawPath \t method:$method \t query:${call.request.queryString()}"
        }

        val isApi = uri == "/api" || uri.startsWith("/api/")

        val noAuthRequired =
            !isApi ||
                    apiWhiteListExact.contains(uri) ||
                    apiWhiteListPrefix.any { prefix ->
                        uri == prefix || uri.startsWith("$prefix/")
                    }

        if (!tokenEnabled || noAuthRequired) return true

        val headers = call.request.headers
        val timestampStr = headers["kano-t"]
        val clientSignature = headers["kano-sign"]
        val authHeader = headers["authorization"]

        if (timestampStr.isNullOrBlank() || clientSignature.isNullOrBlank() || authHeader.isNullOrBlank() || tokenStored.isBlank()) {
            return false
        }

        if (!KanoUtils.constantTimeSha256Equals(authHeader.trim(), tokenStored)) {
            return false
        }

        val clientTimestamp = timestampStr.toLongOrNull() ?: return false
        if (abs(System.currentTimeMillis() - clientTimestamp) > SIGN_TIMESTAMP_TOLERANCE_MS) {
            return false
        }

        //如果是反向代理，则不要进行path过滤
        val signTarget =
            if (uriForAuth == "/api/proxy" || uriForAuth.startsWith("/api/proxy/")) {
                rawPathForSign
            } else {
                uriForAuth       // 其它接口继续用 normalizePath 的结果
            }

        val raw = "minikano$method$signTarget$clientTimestamp"
        val expectedSignature = KanoUtils.hmacSha256Hex(getOrCreateSignKey(context), raw)

        return KanoUtils.constantTimeSha256Equals(
            expectedSignature.lowercase(),
            clientSignature.trim().lowercase()
        )
    }
}
