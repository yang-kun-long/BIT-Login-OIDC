package cn.bit101.bitlogin.manual

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import cn.bit101.bitlogin.login.LoginError
import cn.bit101.bitlogin.login.SsoLogin

/**
 * Verifies the browser-style BIT gateway flow and /gate/getUser.
 *
 * Required environment variables:
 *   BIT_USERNAME, BIT_PASSWORD, BIT_GATEWAY_CALLBACK_URL,
 *   BIT_GATEWAY_CLIENT_ID
 *
 * The callback URL and client ID must be copied from the school's registered
 * portal configuration. This tool deliberately does not provide a default
 * client ID or print cookies, tickets, or one-time callback parameters.
 */
fun main(): Unit = runBlocking {
    val username = env("BIT_USERNAME")
    val password = env("BIT_PASSWORD")
    val callbackUrl = env("BIT_GATEWAY_CALLBACK_URL")
    val clientId = env("BIT_GATEWAY_CLIENT_ID")
    if (listOf(username, password, callbackUrl, clientId).any(String::isBlank)) {
        println("请设置 BIT_USERNAME、BIT_PASSWORD、BIT_GATEWAY_CALLBACK_URL、BIT_GATEWAY_CLIENT_ID")
        return@runBlocking
    }

    val login = SsoLogin(
        smsCodeCallback = { context ->
            println("需要短信二次验证，验证码已发送至 ${context.maskedPhone.ifBlank { "绑定手机" }}")
            prompt("请输入短信验证码: ")
        },
        captchaSolver = { image, _ ->
            val file = Files.write(Files.createTempFile("bit-login-captcha-", ".png"), image)
            println("需要图形验证码，图片已保存到: $file")
            prompt("请输入图形验证码: ")
        },
    )

    try {
        val result = login.login(
            username = username,
            password = password,
            callbackUrl = callbackUrl,
            clientId = clientId,
        )
        val user = result.user ?: login.getUser()
        println("登录成功，统一身份认证账号：${user.username}，姓名：${user.name}")
    } catch (e: LoginError) {
        println("登录或读取姓名失败：${e.message}")
        e.cause?.let { cause ->
            println("诊断：${cause::class.simpleName} ${cause.message?.take(240).orEmpty()}")
        }
    } finally {
        login.session.close()
    }
}

private fun env(name: String): String = System.getenv(name)?.trim().orEmpty()

private fun prompt(label: String): String {
    print(label)
    return readlnOrNull()?.trim().orEmpty()
}
