package com.minikano.f50_sms.modules.auth

import android.content.Context
import com.minikano.f50_sms.utils.KanoLog
import com.minikano.f50_sms.utils.KanoUtils
import com.minikano.f50_sms.utils.KanoUtils.Companion.normalizeLeadingSlashes
import com.minikano.f50_sms.utils.KanoUtils.Companion.normalizePath
import com.minikano.f50_sms.utils.PassHash
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.queryString

object KanoAuth {
    val PREFS_NAME = "kano_ZTE_store"
    val PREF_LOGIN_TOKEN = "login_token"
    val PREF_TOKEN_ENABLED = "login_token_enabled"
    val REQUEST_SECRET_KEY = "minikano_kOyXz0Ciz4V7wR0IeKmJFYFQ20jd"

    // 口令校验结果的短时缓存。口令存储为 12 万轮加盐哈希，逐请求重算会拖垮前端轮询；
    // 命中缓存的请求在换口令后最长 5 分钟内仍可用，过期自动失效
    private const val VERIFY_CACHE_TTL_MS = 5 * 60 * 1000L
    private val verifyCache = HashMap<String, Long>()

    fun invalidateLoginCache() {
        synchronized(verifyCache) { verifyCache.clear() }
    }

    private fun verifyLoginToken(authValue: String, stored: String): Boolean {
        val now = System.currentTimeMillis()
        synchronized(verifyCache) {
            val expiry = verifyCache[authValue]
            if (expiry != null) {
                if (now < expiry) return true
                verifyCache.remove(authValue)
            }
        }

        val ok = PassHash.verify(authValue.toCharArray(), stored)
        if (ok) {
            synchronized(verifyCache) { verifyCache[authValue] = now + VERIFY_CACHE_TTL_MS }
        }
        return ok
    }

    val apiWhiteListExact: Set<String> = setOf(
            "/api/get_custom_head",
            "/api/version_info",
            "/api/need_token",
            "/api/get_theme",
            "/api/SELinux"
        )

    val apiWhiteListPrefix: List<String> = listOf(
        "/api/uploads"
    )

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

        if (!verifyLoginToken(authHeader.trim(), tokenStored)) {
            return false
        }

        val clientTimestamp = timestampStr.toLongOrNull() ?: return false
        //如果是反向代理，则不要进行path过滤
        val signTarget =
            if (uriForAuth == "/api/proxy" || uriForAuth.startsWith("/api/proxy/")) {
                rawPathForSign
            } else {
                uriForAuth       // 其它接口继续用 normalizePath 的结果
            }

        val raw = "minikano$method$signTarget$clientTimestamp"
        val expectedSignature = KanoUtils.HmacSignature(REQUEST_SECRET_KEY, raw)

        return expectedSignature.equals(clientSignature, ignoreCase = true)
    }
}
