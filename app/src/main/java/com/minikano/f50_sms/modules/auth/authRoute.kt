package com.minikano.f50_sms.modules.auth

import android.content.Context
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import org.json.JSONObject

fun Route.authenticatedRoute(context: Context, block: Route.() -> Unit) {
    route("") {
        intercept(ApplicationCallPipeline.Plugins) {
            if (!KanoAuth.checkAuth(call, context)) {
                call.respond(HttpStatusCode.Unauthorized)
                finish() // 阻止后续处理
            }
        }
        block()
    }
}

// 签名密钥按设备随机生成，浏览器端通过该端点获取本设备的密钥
fun Route.signKeyModule(context: Context) {
    get("/api/get_sign_key") {
        call.respondText(
            JSONObject().put("key", KanoAuth.getOrCreateSignKey(context)).toString(),
            ContentType.Application.Json,
            HttpStatusCode.OK
        )
    }
}
