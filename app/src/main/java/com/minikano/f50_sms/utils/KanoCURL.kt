package com.minikano.f50_sms.utils

import android.content.Context
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

class KanoCURL(private val context: Context) {
    companion object {
        // 单线程串行发送：限制并发（最多1线程，空闲30秒后回收），排队而非丢弃。
        // 必须跨实例共享——调用方每次转发都会 new 一个 KanoCURL
        private val sender = ThreadPoolExecutor(0, 1, 30L, TimeUnit.SECONDS, LinkedBlockingQueue())
    }

    // [安全修复] 新增 rawReplacements：占位符在 shell 分词之后再替换，
    // 保证短信正文/发件人等内容始终作为"单个参数"传给 curl，无法注入 -o/--upload-file 等
    fun send(command: String, rawReplacements: Map<String, String> = emptyMap()) {
        sender.execute {
            try {
                KanoLog.w("UFI_TOOLS_LOG_Curl", "正在执行curl命令:$command")
                var args = KanoUtils.parseShellArgs(command.replaceFirst("curl", ""))
                if (rawReplacements.isNotEmpty()) {
                    args = args.map { arg ->
                        var a = arg
                        for ((k, v) in rawReplacements) {
                            a = a.replace(k, v)
                        }
                        a.replace("\u0000", "") // argv 中不允许 NUL
                    }
                }
                val result = ShellKano.executeShellFromAssetsSubfolderWithArgs(
                    context,
                    "shell/curl",
                    *args.toTypedArray(),
                    timeoutMs = 10000
                ) ?: throw Exception("runShellCommand为null")
                KanoLog.w("UFI_TOOLS_LOG_Curl", "执行curl命令结果：$result")
            } catch (e: Exception) {
                KanoLog.e("UFI_TOOLS_LOG_Curl", "curl请求失败: ${e.message}", e)
            }
        }
    }
}
