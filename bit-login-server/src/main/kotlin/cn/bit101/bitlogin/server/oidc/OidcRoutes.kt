package cn.bit101.bitlogin.server.oidc

import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.Date
import java.util.Base64
import cn.bit101.bitlogin.server.auth.ChallengeHandle
import cn.bit101.bitlogin.server.auth.ChallengeError

fun Route.oidcRoutes(
    config: OidcConfig,
    signingKey: OidcSigningKey,
    grants: OidcGrantStore,
    authenticator: IdentityAuthenticator,
    blocklist: OidcBlocklistStore,
) {
    get("/.well-known/openid-configuration") {
        call.response.headers.append(HttpHeaders.CacheControl, "public, max-age=300")
        call.respond(buildJsonObject {
            put("issuer", config.issuer)
            put("authorization_endpoint", "${config.issuer}/oauth/authorize")
            put("token_endpoint", "${config.issuer}/oauth/token")
            put("userinfo_endpoint", "${config.issuer}/oauth/userinfo")
            put("jwks_uri", "${config.issuer}/jwks")
            put("response_types_supported", Json.parseToJsonElement("[\"code\"]"))
            put("response_modes_supported", Json.parseToJsonElement("[\"query\"]"))
            put("grant_types_supported", Json.parseToJsonElement("[\"authorization_code\"]"))
            put("subject_types_supported", Json.parseToJsonElement("[\"public\"]"))
            put("id_token_signing_alg_values_supported", Json.parseToJsonElement("[\"RS256\"]"))
            put("token_endpoint_auth_methods_supported", Json.parseToJsonElement("[\"none\"]"))
            put("scopes_supported", Json.parseToJsonElement("[\"openid\",\"student_id\"]"))
            put("claims_supported", Json.parseToJsonElement("[\"sub\",\"student_id\"]"))
            put("code_challenge_methods_supported", Json.parseToJsonElement("[\"S256\"]"))
        })
    }

    get("/jwks") {
        call.response.headers.append(HttpHeaders.CacheControl, "public, max-age=300")
        call.respond(signingKey.jwks())
    }

    get("/oauth/authorize") {
        call.noStore()
        val query = call.request.queryParameters
        val clientId = query["client_id"].orEmpty()
        val redirectUri = query["redirect_uri"].orEmpty()
        val state = query["state"].orEmpty()
        if (clientId != config.clientId || config.clientId.isBlank()) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_client", "Unknown client")
            return@get
        }
        if (redirectUri !in config.redirectUris) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Unregistered redirect_uri")
            return@get
        }
        if (!SAFE_STATE.matches(state) || state.isBlank()) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "state is required")
            return@get
        }

        val responseType = query["response_type"]
        if (responseType != "code") {
            call.redirectOAuthError(redirectUri, state, "unsupported_response_type")
            return@get
        }
        val scopes = query["scope"].orEmpty().split(' ').filter(String::isNotBlank).toSet()
        if (scopes != ALLOWED_SCOPES) {
            call.redirectOAuthError(redirectUri, state, "invalid_scope")
            return@get
        }
        val nonce = query["nonce"].orEmpty()
        val codeChallenge = query["code_challenge"].orEmpty()
        if (!SAFE_STATE.matches(nonce) || nonce.isBlank() || !CODE_CHALLENGE.matches(codeChallenge) || query["code_challenge_method"] != "S256") {
            call.redirectOAuthError(redirectUri, state, "invalid_request")
            return@get
        }

        val flow = grants.createFlow(
            OidcAuthorizationRequest(
                clientId = clientId,
                redirectUri = redirectUri,
                state = state,
                nonce = nonce,
                codeChallenge = codeChallenge,
                scope = scopes.sorted().joinToString(" "),
            ),
        )
        call.respondHtml(loginPage(flow))
    }

    post("/oauth/login") {
        call.noStore()
        val params = call.receiveParameters()
        val flow = grants.getFlow(params["flow_id"].orEmpty())
        if (flow == null || !grants.hasValidCsrf(flow, params["csrf"].orEmpty())) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            return@post
        }
        if (flow.challenge != null) {
            call.respondOAuthError(HttpStatusCode.Conflict, "invalid_request", "Login already started")
            return@post
        }
        val username = params["username"]?.trim().orEmpty()
        val password = params["password"].orEmpty()
        if (username.length !in 1..64 || username.any(Char::isISOControl) || password.length !in 1..1024) {
            call.respondHtml(loginPage(flow, "请输入有效的学工号和密码"), HttpStatusCode.BadRequest)
            return@post
        }
        val challenge = try {
            authenticator.start(username, password)
        } catch (_: Exception) {
            call.respondHtml(loginPage(flow, "当前无法连接统一身份认证，请稍后重试"), HttpStatusCode.ServiceUnavailable)
            return@post
        }
        if (!grants.setChallenge(flow.id, challenge)) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            return@post
        }
        call.respondRedirect("/oauth/pending?flow_id=${flow.id}")
    }

    get("/oauth/pending") {
        call.noStore()
        val flow = grants.getFlow(call.request.queryParameters["flow_id"].orEmpty())
        if (flow == null) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            return@get
        }
        val challenge = flow.challenge
        if (challenge == null) {
            call.respondHtml(loginPage(flow))
            return@get
        }
        val snapshot = try {
            authenticator.status(challenge)
        } catch (_: ChallengeError) {
            val retry = grants.resetChallenge(flow.id)
            if (retry == null) call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            else call.respondHtml(loginPage(retry, "登录已过期，请重新登录"), HttpStatusCode.Unauthorized)
            return@get
        } catch (_: Exception) {
            call.respondOAuthError(HttpStatusCode.ServiceUnavailable, "temporarily_unavailable", "Login status is temporarily unavailable")
            return@get
        }
        when (snapshot["status"] as? String) {
            "authenticated" -> {
                val subject = authenticator.authenticatedSubject(challenge)
                if (subject.isNullOrBlank()) {
                    val retry = grants.resetChallenge(flow.id)
                    if (retry == null) call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
                    else call.respondHtml(loginPage(retry, "无法确认登录账号，请重新登录"), HttpStatusCode.Unauthorized)
                    return@get
                }
                if (blocklist.contains(subject)) {
                    grants.resetChallenge(flow.id)
                    call.respondHtml(loginPage(grants.getFlow(flow.id) ?: flow, "该学工号暂不可通过统一登录"), HttpStatusCode.Forbidden)
                    return@get
                }
                val redirect = grants.completeLogin(flow.id, subject)
                if (redirect == null) call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
                else call.respondRedirect(redirect)
            }
            "waiting_sms" -> call.respondHtml(
                challengePage(flow, "sms", "短信验证码", snapshot["masked_phone"] as? String ?: "", null),
            )
            "waiting_captcha" -> call.respondHtml(
                challengePage(flow, "captcha", "图形验证码", "", snapshot["captcha_image"] as? String),
            )
            "failed", "expired", "cancelled" -> {
                val retry = grants.resetChallenge(flow.id)
                if (retry == null) call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
                else call.respondHtml(loginPage(retry, "登录失败，请检查学工号和密码后重试"), HttpStatusCode.Unauthorized)
            }
            else -> call.respondHtml(pendingPage(flow))
        }
    }

    post("/oauth/continue") {
        call.noStore()
        val params = call.receiveParameters()
        val flow = grants.getFlow(params["flow_id"].orEmpty())
        if (flow == null || !grants.hasValidCsrf(flow, params["csrf"].orEmpty())) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            return@post
        }
        val challenge = flow.challenge
        if (challenge == null) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Login request expired")
            return@post
        }
        try {
            val answer = params["answer"].orEmpty()
            when (params["kind"]) {
                "sms" -> authenticator.submitSms(challenge, answer)
                "captcha" -> authenticator.submitCaptcha(challenge, answer)
                else -> {
                    call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Unknown challenge")
                    return@post
                }
            }
        } catch (_: Exception) {
        val snapshot = try {
            authenticator.status(challenge)
        } catch (_: Exception) {
            emptyMap()
        }
            val kind = when (snapshot["status"]) {
                "waiting_sms" -> "sms"
                "waiting_captcha" -> "captcha"
                else -> null
            }
            if (kind == null) call.respondHtml(pendingPage(flow))
            else call.respondHtml(
                challengePage(
                    flow,
                    kind,
                    if (kind == "sms") "短信验证码" else "图形验证码",
                    snapshot["masked_phone"] as? String ?: "",
                    snapshot["captcha_image"] as? String,
                    "验证码无效，请重试",
                ),
                HttpStatusCode.BadRequest,
            )
            return@post
        }
        call.respondRedirect("/oauth/pending?flow_id=${flow.id}")
    }

    post("/oauth/token") {
        call.noStore()
        val params = call.receiveParameters()
        if (call.request.headers[HttpHeaders.Authorization] != null || params["client_secret"] != null) {
            call.respondOAuthError(HttpStatusCode.Unauthorized, "invalid_client", "This is a public PKCE client")
            return@post
        }
        if (params["grant_type"] != "authorization_code" || params["client_id"] != config.clientId) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_request", "Invalid token request")
            return@post
        }
        val grant = grants.consumeAuthorizationCode(
            code = params["code"].orEmpty(),
            clientId = params["client_id"].orEmpty(),
            redirectUri = params["redirect_uri"].orEmpty(),
            codeVerifier = params["code_verifier"].orEmpty(),
        )
        if (grant == null) {
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_grant", "Authorization code is invalid, expired, or already used")
            return@post
        }
        if (blocklist.contains(grant.subject)) {
            grants.revokeSubject(grant.subject)
            call.respondOAuthError(HttpStatusCode.BadRequest, "invalid_grant", "Authorization code is invalid, expired, or already used")
            return@post
        }
        val now = System.currentTimeMillis()
        val expiresAt = now + config.accessTokenTtlSeconds * 1000L
        val idToken = signingKey.sign(
            JWTClaimsSet.Builder()
                .issuer(config.issuer)
                .subject(grant.subject)
                .audience(config.clientId)
                .issueTime(Date(now))
                .expirationTime(Date(expiresAt))
                .claim("nonce", grant.nonce)
                .claim("student_id", grant.subject)
                .build(),
        )
        val accessToken = grants.issueAccessToken(grant.subject)
        call.respond(buildJsonObject {
            put("access_token", accessToken)
            put("token_type", "Bearer")
            put("expires_in", config.accessTokenTtlSeconds)
            put("scope", "openid student_id")
            put("id_token", idToken)
        })
    }

    get("/oauth/userinfo") {
        call.noStore()
        val header = call.request.headers[HttpHeaders.Authorization].orEmpty()
        val token = header.takeIf { it.startsWith("Bearer ", ignoreCase = true) }?.substringAfter(' ')?.trim().orEmpty()
        val subject = if (token.isBlank()) null else grants.subjectForAccessToken(token)
        if (subject == null || blocklist.contains(subject)) {
            call.response.headers.append("WWW-Authenticate", "Bearer error=\"invalid_token\"")
            call.respondOAuthError(HttpStatusCode.Unauthorized, "invalid_token", "A valid bearer token is required")
            return@get
        }
        call.respond(buildJsonObject {
            put("sub", subject)
            put("student_id", subject)
        })
    }
}

private fun loginPage(flow: OidcLoginFlow, error: String? = null): String = page(
    title = "BIT 身份认证",
    content = buildString {
        append("<h1>BIT 身份认证</h1>")
        if (error != null) append("<p class=\"error\">${escapeHtml(error)}</p>")
        append("<form method=\"post\" action=\"/oauth/login\">")
        append(hidden("flow_id", flow.id))
        append(hidden("csrf", flow.csrf))
        append("<label for=\"username\">学号 / 工号</label>")
        append("<input id=\"username\" name=\"username\" autocomplete=\"username\" required maxlength=\"64\" autofocus>")
        append("<label for=\"password\">密码</label>")
        append("<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required maxlength=\"1024\">")
        append("<button type=\"submit\">登录</button></form>")
    },
)

private fun challengePage(
    flow: OidcLoginFlow,
    kind: String,
    label: String,
    maskedPhone: String,
    imageBase64: String?,
    error: String? = null,
): String = page(
    title = "BIT 身份认证",
    content = buildString {
        append("<h1>BIT 身份认证</h1>")
        if (kind == "sms" && maskedPhone.isNotBlank()) append("<p>${escapeHtml(maskedPhone)}</p>")
        if (kind == "captcha" && !imageBase64.isNullOrBlank()) {
            val bytes = runCatching { Base64.getDecoder().decode(imageBase64) }.getOrNull()
            val mime = if (bytes?.take(2) == listOf(0xff.toByte(), 0xd8.toByte())) "image/jpeg" else "image/png"
            append("<img class=\"captcha\" src=\"data:$mime;base64,$imageBase64\" alt=\"验证码\">")
        }
        if (error != null) append("<p class=\"error\">${escapeHtml(error)}</p>")
        append("<form method=\"post\" action=\"/oauth/continue\">")
        append(hidden("flow_id", flow.id))
        append(hidden("csrf", flow.csrf))
        append(hidden("kind", kind))
        append("<label for=\"answer\">$label</label>")
        append("<input id=\"answer\" name=\"answer\" autocomplete=\"one-time-code\" required maxlength=\"32\" autofocus>")
        append("<button type=\"submit\">确认</button></form>")
    },
)

private fun pendingPage(flow: OidcLoginFlow): String = page(
    title = "BIT 身份认证",
    content = "<h1>BIT 身份认证</h1><p>正在验证</p>",
    head = "<meta http-equiv=\"refresh\" content=\"1;url=/oauth/pending?flow_id=${flow.id}\">",
)

private fun hidden(name: String, value: String): String =
    "<input type=\"hidden\" name=\"$name\" value=\"${escapeHtml(value)}\">"

private fun page(title: String, content: String, head: String = ""): String = """
    <!doctype html>
    <html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>$head<style>
    :root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#172033;background:#f5f7fa}
    body{margin:0;min-height:100vh;display:grid;place-items:center}
    main{box-sizing:border-box;width:min(100% - 32px,380px);padding:28px 24px;background:#fff;border:1px solid #dfe5ec;border-radius:6px}
    h1{font-size:21px;margin:0 0 24px;font-weight:650}
    form{display:grid;gap:10px}label{font-size:14px;color:#354052;margin-top:4px}
    input{box-sizing:border-box;width:100%;height:42px;padding:8px 10px;border:1px solid #aeb8c5;border-radius:4px;font-size:16px}
    input:focus{outline:2px solid #9bc2ef;outline-offset:1px;border-color:#346da8}
    button{height:42px;margin-top:10px;border:0;border-radius:4px;background:#245c91;color:white;font-size:15px;font-weight:600;cursor:pointer}
    button:hover{background:#194b79}.error{color:#a92828;font-size:14px}.captcha{display:block;max-width:100%;height:auto;image-rendering:auto}
    </style></head><body><main>$content</main></body></html>
""".trimIndent()

private fun escapeHtml(value: String): String = value
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace("\"", "&quot;")
    .replace("'", "&#39;")

private fun ApplicationCall.noStore() {
    response.headers.append(HttpHeaders.CacheControl, "no-store, no-cache, max-age=0")
    response.headers.append(HttpHeaders.Pragma, "no-cache")
    response.headers.append("Referrer-Policy", "no-referrer")
    response.headers.append("X-Content-Type-Options", "nosniff")
    response.headers.append("X-Frame-Options", "DENY")
    response.headers.append("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

private suspend fun ApplicationCall.respondHtml(value: String, status: HttpStatusCode = HttpStatusCode.OK) {
    noStore()
    respondText(value, ContentType.parse("text/html; charset=utf-8"), status)
}

private suspend fun ApplicationCall.respondOAuthError(status: HttpStatusCode, error: String, description: String) {
    noStore()
    respond(status, buildJsonObject {
        put("error", error)
        put("error_description", description)
    })
}

private suspend fun ApplicationCall.redirectOAuthError(uri: String, state: String, error: String) {
    val location = URLBuilder(uri).apply {
        parameters.append("error", error)
        parameters.append("state", state)
    }.buildString()
    respondRedirect(location)
}

private val SAFE_STATE = Regex("[A-Za-z0-9._~-]{1,512}")
private val CODE_CHALLENGE = Regex("[A-Za-z0-9_-]{43}")
private val ALLOWED_SCOPES = setOf("openid", "student_id")
