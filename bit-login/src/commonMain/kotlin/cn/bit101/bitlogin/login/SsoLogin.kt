package cn.bit101.bitlogin.login

import cn.bit101.bitlogin.Config
import cn.bit101.bitlogin.http.HttpClient
import cn.bit101.bitlogin.http.HttpResponse
import cn.bit101.bitlogin.sso.BitSsoClient
import cn.bit101.bitlogin.sso.BitSsoError
import cn.bit101.bitlogin.sso.CaptchaSolver
import cn.bit101.bitlogin.sso.SessionSsoTransport
import cn.bit101.bitlogin.sso.SmsCodeCallback
import cn.bit101.bitlogin.sso.SsoHttpException
import cn.bit101.bitlogin.sso.SsoLoginResult
import cn.bit101.bitlogin.sso.SsoUser
import cn.bit101.bitlogin.util.PythonUrlEncoding
import cn.bit101.bitlogin.util.describeNetworkFailure
import cn.bit101.bitlogin.util.uriHost
import cn.bit101.bitlogin.util.uriQuery

class SsoLogin(
    baseUrl: String = "",
    session: HttpClient? = null,
    captchaSolver: CaptchaSolver? = null,
    smsCodeCallback: SmsCodeCallback? = null,
) {
    var session: HttpClient = (session ?: HttpClient()).also { s ->
            // Always apply browser default headers, even on externally-provided
            // sessions. Python BitSsoClient.__init__ mutates session.headers
            // unconditionally; without a User-Agent the CAS server returns a
            // non-login page and the parser fails.
            BitSsoClient.BROWSER_DEFAULT_HEADERS.forEach { (k, v) ->
                s.headers[k] = v
            }
        }
        internal set

    private val ssoBase: String = if (baseUrl.isNotBlank() && "/cas/v1/tickets" !in baseUrl)
        baseUrl.trimEnd('/') else SSO_BASE

    val captchaSolver: CaptchaSolver? = captchaSolver
    val smsCodeCallback: SmsCodeCallback? = smsCodeCallback

    private val transport = SessionSsoTransport { this.session }

    private val client: BitSsoClient = BitSsoClient(
        baseUrl = ssoBase,
        transport = transport,
        captchaSolver = captchaSolver,
    )

    suspend fun login(
        username: String,
        password: String,
        callbackUrl: String = "",
        webvpnMode: Boolean = false,
        retries: Int = 0,
        trustDevice: Boolean = false,
        smsCodeCallback: SmsCodeCallback? = null,
        captchaSolver: CaptchaSolver? = null,
        clientId: String? = null,
    ): LoginResult {
        if (callbackUrl.isBlank()) throw LoginError("callback_url must not be empty")
        return try {
            val browserFlow = !clientId.isNullOrBlank()
            // Keep the first redirect visible. The browser follows this
            // location while retaining the CAS cookies, and the gateway may
            // turn its one-time ticket into a code/state callback on that
            // navigation. HttpClient's followed response does not expose the
            // original Location header, so the SDK follows it explicitly.
            val result = client.loginPassword(
                username = username,
                password = password,
                service = callbackUrl,
                smsCodeCallback = smsCodeCallback ?: this.smsCodeCallback,
                captchaSolver = captchaSolver ?: this.captchaSolver,
                trustDevice = trustDevice,
                followRedirects = false,
                clientId = clientId,
            )
            val callback = ticketCallback(result, callbackUrl)
            val user = if (browserFlow) {
                followBrowserCallback(result)
                client.getUser()
            } else null
            LoginResult(
                cookieJson = session.cookieMap(),
                callback = callback,
                ticket = result.ticket,
                user = user,
            )
        } catch (e: BitSsoError) {
            // Python's login wrapper maps requests.HTTPError to one of these
            // Chinese messages based on status code. The 4xx/5xx fallthrough
            // replaces what used to be a confusing ConfigurationError when the
            // SSO server replied with an error page.
            val message = when (e) {
                is SsoHttpException -> when (e.statusCode) {
                    429 -> "统一身份认证请求过于频繁，请稍后重试"
                    in 500..599 -> "统一身份认证服务暂时不可用（HTTP ${e.statusCode}）"
                    in 400..499 -> "统一身份认证请求失败（HTTP ${e.statusCode}）"
                    else -> "统一身份认证请求失败，请稍后重试"
                }
                else -> e.message ?: "SSO error"
            }
            throw LoginError(message, e)
        } catch (e: Throwable) {
            val netMsg = describeNetworkFailure(e)
            throw LoginError(netMsg ?: (e.message ?: "unknown error"), e)
        }
    }

    /**
     * Read the identity associated with this login session from the BIT
     * gateway. Browser-style logins also expose the same value in
     * [LoginResult.user].
     */
    suspend fun getUser(): SsoUser = try {
        client.getUser()
    } catch (e: BitSsoError) {
        throw LoginError(e.message ?: "无法读取统一身份认证用户信息", e)
    } catch (e: Throwable) {
        val netMsg = describeNetworkFailure(e)
        throw LoginError(netMsg ?: (e.message ?: "无法读取统一身份认证用户信息"), e)
    }

    private fun ticketCallback(result: SsoLoginResult, service: String): String {
        val response = result.response as? HttpResponse
        val location = response?.location()
        val callback = when {
            !location.isNullOrBlank() -> PythonUrlEncoding.urlJoin(result.finalUrl, location)
            !result.ticket.isNullOrBlank() -> service + (if ("?" in service) "&" else "?") + "ticket=${result.ticket}"
            else -> result.finalUrl
        }
        val callbackTicket = uriQuery(callback)?.split("&")
            ?.firstOrNull { it.startsWith("ticket=") }?.substringAfter("=")
            ?.let { PythonUrlEncoding.unquote(it) }
        val query = uriQuery(callback).orEmpty()
        val hasCodeCallback = query.split("&").any { it.startsWith("code=") } &&
            query.split("&").any { it.startsWith("state=") }
        if ((callbackTicket.isNullOrBlank()) && result.ticket.isNullOrBlank() && !hasCodeCallback) {
            throw LoginError("CAS did not issue a service ticket")
        }
        return callback
    }

    private suspend fun followBrowserCallback(result: SsoLoginResult) {
        val response = result.response as? HttpResponse ?: return
        val location = response.location()?.takeIf { it.isNotBlank() } ?: return
        var callback = PythonUrlEncoding.urlJoin(result.finalUrl, location)
        val trustedHost = uriHost(callback) ?: uriHost(result.finalUrl)
        // The gateway callback is allowed to return an authorization error
        // while still establishing the browser SESSION; /gate/getUser below
        // is the authoritative check. Do not discard cookies on a 401 here.
        // The gateway starts its OAuth session only for a browser navigation.
        // A generic */* Accept header gets a 401 from cas-success; send the
        // same document-navigation headers as the portal browser so its
        // OAuth authorization redirects complete and set the /gate SESSION.
        var referer = result.finalUrl
        repeat(MAX_BROWSER_REDIRECTS) {
            val navigation = session.get(
                callback,
                headers = mapOf(
                    "Accept" to "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Sec-Fetch-Dest" to "document",
                    "Sec-Fetch-Mode" to "navigate",
                    "Sec-Fetch-Site" to "same-origin",
                    "Upgrade-Insecure-Requests" to "1",
                    "Referer" to referer,
                ),
                // Ktor rejects HTTPS → HTTP redirects before returning the
                // response. Keep this request in no-follow mode and process
                // the chain below so only the known same-host downgrade is
                // upgraded back to HTTPS.
                allowRedirects = false,
            )
            if (!navigation.isRedirect()) return
            val nextLocation = navigation.location()?.takeIf { it.isNotBlank() } ?: return
            val next = PythonUrlEncoding.urlJoin(navigation.url, nextLocation)
            // Do not carry a browser session onto an unrelated plaintext
            // host. The gateway's known downgrade is same-host and is handled
            // by upgradeSameHostHttpRedirect below.
            if (isCrossHostHttpRedirect(next, trustedHost)) return
            referer = navigation.url
            callback = upgradeSameHostHttpRedirect(next, trustedHost)
        }
        throw LoginError("门户回调重定向次数过多")
    }

    companion object {
        const val SSO_BASE = "https://sso.bit.edu.cn"
        private const val MAX_BROWSER_REDIRECTS = 12
    }
}

/**
 * The BIT gateway currently emits one HTTP redirect from its HTTPS OAuth
 * endpoint. Preserve the browser's effective HTTPS navigation when that
 * redirect stays on the same host; leave cross-host redirects untouched so
 * the caller never silently upgrades trust for an unrelated service.
 */
internal fun upgradeSameHostHttpRedirect(url: String, trustedHost: String?): String {
    if (trustedHost.isNullOrBlank() || !url.startsWith("http://", ignoreCase = true)) return url
    if (!uriHost(url).equals(trustedHost, ignoreCase = true)) return url
    val authorityAndPath = url.substringAfter("://", missingDelimiterValue = url)
    val authorityEnd = authorityAndPath.indexOfAny(charArrayOf('/', '?', '#'))
    val authority = if (authorityEnd >= 0) authorityAndPath.substring(0, authorityEnd) else authorityAndPath
    val suffix = if (authorityEnd >= 0) authorityAndPath.substring(authorityEnd) else ""
    val httpsAuthority = authority.removeSuffix(":80")
    return "https://$httpsAuthority$suffix"
}

private fun isCrossHostHttpRedirect(url: String, trustedHost: String?): Boolean {
    if (!url.startsWith("http://", ignoreCase = true)) return false
    val targetHost = uriHost(url)
    return targetHost.isNullOrBlank() || trustedHost.isNullOrBlank() ||
        !targetHost.equals(trustedHost, ignoreCase = true)
}

internal val HttpResponse.isOk get() = status == 200
