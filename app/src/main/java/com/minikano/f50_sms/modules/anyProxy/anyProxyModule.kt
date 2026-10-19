package com.minikano.f50_sms.modules.at

import android.content.Context
import com.minikano.f50_sms.modules.BASE_TAG
import com.minikano.f50_sms.utils.KanoLog
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.*
import io.ktor.server.routing.Route
import io.ktor.util.toByteArray
import okhttp3.*
import okhttp3.Headers
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

val unsafeHeaderNames = setOf(
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host", "content-length", "expect",
    "referer", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "via", "x-forwarded-for",
    "x-forwarded-proto", "x-real-ip", "authorization", "content-security-policy",
    "content-security-policy-report-only", "clear-site-data"
)

private val proxyHttpClient: OkHttpClient = OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(8, TimeUnit.SECONDS)
    .writeTimeout(8, TimeUnit.SECONDS)
    .callTimeout(30, TimeUnit.SECONDS)
    .retryOnConnectionFailure(false)
    .connectionPool(ConnectionPool(8, 2, TimeUnit.MINUTES))
    .dispatcher(Dispatcher().apply {
        maxRequests = 32
        maxRequestsPerHost = 8
    })
    // 目标校验放在 Dns 里做：校验与连接使用同一次解析结果，先校验后连接的两次解析可被 DNS rebinding 绕过
    .dns(object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            if (forbiddenDomains.any { it.equals(hostname, ignoreCase = true) }) {
                throw UnknownHostException("proxy target domain is not allowed: $hostname")
            }
            val addresses = InetAddress.getAllByName(hostname).toList()
            if (addresses.any {
                    it.isAnyLocalAddress || // 0.0.0.0
                    it.isLoopbackAddress || // 127.0.0.1, ::1
                    it.isLinkLocalAddress || // 169.254.x.x
                    it.isSiteLocalAddress // 192.168.x.x, 10.x.x.x, 172.16.x.x
                }
            ) {
                throw UnknownHostException("proxy target address is not allowed: $hostname")
            }
            return addresses
        }
    })
    .addInterceptor { chain ->
        val request = chain.request().newBuilder()
            .removeHeader("Accept-Encoding")
            .addHeader("Accept-Encoding", "identity")
            .build()
        chain.proceed(request)
    }
    .build()


fun isSafeHeader(header: String): Boolean {
    return header.lowercase() !in unsafeHeaderNames
}

val forbiddenDomains = listOf(
    "ufi.ztedevice.com"
)

fun Route.anyProxyModule(context: Context) {
    val TAG = "[$BASE_TAG]_anyProxyModule"

    route("/api/proxy/{...}") {
        handle {
            val rawPath = call.request.uri.removePrefix("/api/proxy/")
            val targetUrl = rawPath.removePrefix("--")

            // 目标地址校验在 OkHttp Dns 中完成，这里只做基本格式检查
            val targetUri = try {
                URI(targetUrl)
            } catch (e: Exception) {
                null
            }
            if (targetUri == null ||
                targetUri.scheme?.lowercase() !in listOf("http", "https") ||
                targetUri.host.isNullOrBlank()
            ) {
                call.respond(HttpStatusCode.Forbidden, "Access to target address is not allowed.")
                return@handle
            }

            val method = call.request.httpMethod.value

            val okHttpClient = proxyHttpClient

            // 构建请求体（如果有）
            val requestBody = if (call.request.httpMethod in listOf(
                    HttpMethod.Post, HttpMethod.Put, HttpMethod.Patch
                )
            ) {
                val bodyBytes = call.receiveChannel().toByteArray()
                bodyBytes.toRequestBody(call.request.contentType()?.toString()?.toMediaTypeOrNull())
            } else null

            // 构建请求头
            val headersBuilder = Headers.Builder()
            for ((key, values) in call.request.headers.entries()) {
                if (key.startsWith("kano-", ignoreCase = true)) {
                    KanoLog.d(TAG,"代理请求头检测到$key=$values，已去掉前缀")
                    if(key.contains("kano-cookie", ignoreCase = true)) {
                        headersBuilder.add("Cookie", values.first())
                    }else {
                        headersBuilder.addUnsafeNonAscii(key.removePrefix("kano-"), values.first())
                    }
                } else if (isSafeHeader(key)) {
                    headersBuilder.addUnsafeNonAscii(key, values.first())
                }
            }

            val request = Request.Builder()
                .url(targetUrl)
                .method(method, requestBody)
                .headers(headersBuilder.build())
                .build()

            try {
                val response = okHttpClient.newCall(request).execute()
                val responseBody = response.body
                val statusCode = response.code
                val contentType = responseBody?.contentType()?.toString()?.let { ContentType.parse(it) }

                // 处理响应头
                response.headers.names().forEach { name ->
                    val lowerName = name.lowercase()
                    val values = response.headers.values(name)

                    if (lowerName == "set-cookie") {
                        values.forEach { rawCookie ->
                            call.response.headers.append("Kano-SetCk", rawCookie)
                            call.response.headers.append("Kano-Set-Cookie", rawCookie)
                        }
                    } else if (isSafeHeader(name)) {
                        values.forEach { value ->
                            call.response.headers.append(name, value)
                        }
                    }
                }

                // 固定为 * 且不携带凭据：反射 Origin 并允许凭据会让任意网页借用户浏览器跨域读取代理响应
                call.response.headers.append("Access-Control-Allow-Origin", "*")
                call.response.headers.append("Access-Control-Expose-Headers", "Kano-SetCk")

                if (responseBody != null) {
                    if (contentType?.match(ContentType.Text.Html) == true) {
                        // HTML 模式，替换资源路径
                        val html = responseBody.string()
                        val baseUrl = targetUrl.substringBeforeLast("/").substringBefore("?")
                        val proxyPrefix = "/api/proxy/--$baseUrl"
                        val rewrittenHtml = html.replace("""(src|href)\s*=\s*["']/(.*?)["']""".toRegex()) {
                            val attr = it.groupValues[1]
                            val path = it.groupValues[2]
                            """$attr="$proxyPrefix/$path""""
                        }
                        call.respondText(rewrittenHtml, contentType, HttpStatusCode.fromValue(statusCode))
                    } else {
                        // 非 HTML，使用流式响应
                        call.respondOutputStream(contentType, HttpStatusCode.fromValue(statusCode)) {
                            responseBody.byteStream().use { input ->
                                input.copyTo(this)
                            }
                        }
                    }
                } else {
                    call.respond(HttpStatusCode.BadGateway, "Empty response body")
                }
            } catch (e: Exception) {
                call.respond(HttpStatusCode.BadGateway, "Proxy error: ${e.message}")
            }
        }
    }
}