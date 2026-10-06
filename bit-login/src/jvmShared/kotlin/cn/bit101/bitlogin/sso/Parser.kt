package cn.bit101.bitlogin.sso

import java.net.URI
import org.jsoup.Jsoup

actual object SsoParser {
    actual fun parseLoginPage(html: String, responseUrl: String): ParsedLoginPage {
        val document = Jsoup.parse(html)
        val execution = text(document, "login-page-flowkey")
        val cryptoKey = text(document, "login-croypto")
        val page = if (execution.isNotEmpty() && cryptoKey.isNotEmpty()) {
            LoginPage(
                execution = execution,
                cryptoKey = cryptoKey,
                formAction = resolveFormAction(responseUrl, document.selectFirst("form")?.attr("action")),
                recaptchaVendor = text(document, "recaptchaVendor"),
                riskSystem = text(document, "riskSystemSwitch"),
                targetSystem = text(document, "targetSystem"),
                siteId = text(document, "siteId"),
            )
        } else {
            null
        }
        return ParsedLoginPage(page, text(document, "login-error-msg"), text(document, "login-error-code"))
    }

    actual fun parseSecondFactorPage(html: String, responseUrl: String): SecondFactorPage? {
        val document = Jsoup.parse(html)
        val execution = text(document, "login-page-flowkey")
        val userObjectId = text(document, "user-object-id")
        val hasGatewayMarker = html.contains("secondSmsLoginForm") ||
            html.contains("second-auth-tip") || html.contains("cas-gateway")
        if (execution.isEmpty() || userObjectId.isEmpty() || !hasGatewayMarker) return null
        return SecondFactorPage(
            execution = execution,
            formAction = resolveFormAction(responseUrl, document.selectFirst("form")?.attr("action")),
            userObjectId = userObjectId,
            userId = text(document, "second-auth-user-id"),
            phone = text(document, "phone-number"),
        )
    }

    private fun text(document: org.jsoup.nodes.Document, id: String): String = document.getElementById(id)?.text()?.trim().orEmpty()

    private fun resolveFormAction(responseUrl: String, action: String?): String {
        // An omitted HTML form action submits to the current document URL,
        // including its query string. CAS carries service/client_id there,
        // which selects the success callback and establishes the gateway
        // session used by /gate/getUser. Resolving an invented "login" path
        // silently dropped those query parameters.
        if (action.isNullOrBlank()) return responseUrl
        return URI(responseUrl).resolve(action).toString()
    }
}
