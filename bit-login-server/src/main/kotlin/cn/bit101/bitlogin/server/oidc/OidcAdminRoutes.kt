package cn.bit101.bitlogin.server.oidc

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import cn.bit101.bitlogin.server.auth.ChallengeError

fun Route.oidcAdminRoutes(
    config: OidcConfig,
    admins: OidcAdminStore,
    blocklist: OidcBlocklistStore,
    grants: OidcGrantStore,
    authenticator: IdentityAuthenticator,
    signingKey: OidcSigningKey? = null,
    audit: OidcAuditStore? = null,
) {
    get("/admin") {
        call.adminNoStore()
        val session = admins.getSession(call.request.cookies[ADMIN_COOKIE])
        if (session == null) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), queryMessage(call.request.queryParameters["status"])))
        } else {
            call.respondAdminHtml(
                adminDashboard(
                    session = session,
                    config = config,
                    entries = blocklist.list(),
                    runtimeStats = grants.runtimeStats(),
                    signingKey = signingKey,
                    auditEntries = audit?.list(12).orEmpty(),
                    auditCount = audit?.count() ?: 0,
                    message = queryMessage(call.request.queryParameters["status"]),
                ),
            )
        }
    }

    get("/admin/export/oidc.json") {
        call.adminNoStore()
        requireAdminSession(call, admins, config) ?: return@get
        call.response.headers.append(HttpHeaders.ContentDisposition, "attachment; filename=\"oidc-integration.json\"")
        call.respondText(oidcIntegrationJson(config, signingKey).toString(), ContentType.Application.Json)
    }

    get("/admin/export/oidc.md") {
        call.adminNoStore()
        requireAdminSession(call, admins, config) ?: return@get
        call.response.headers.append(HttpHeaders.ContentDisposition, "attachment; filename=\"oidc-integration.md\"")
        call.respondText(oidcIntegrationMarkdown(config, signingKey), ContentType.Text.Plain.withCharset(Charsets.UTF_8))
    }

    post("/admin/login") {
        call.adminNoStore()
        val params = call.receiveParameters()
        val flow = admins.getFlow(params["flow_id"].orEmpty())
        if (flow == null || !admins.hasValidCsrf(flow, params["csrf"].orEmpty())) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已过期，请重试"), HttpStatusCode.BadRequest)
            return@post
        }
        if (flow.challenge != null) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已使用，请重试"), HttpStatusCode.Conflict)
            return@post
        }
        val username = params["username"]?.trim().orEmpty()
        val password = params["password"].orEmpty()
        if (!OidcBlocklistStore.STUDENT_ID.matches(username) || password.length !in 1..1024) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "请输入有效的学工号和密码"), HttpStatusCode.BadRequest)
            return@post
        }
        val challenge = try {
            authenticator.start(username, password)
        } catch (_: Exception) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "当前无法连接统一身份认证，请稍后重试"), HttpStatusCode.ServiceUnavailable)
            return@post
        }
        if (!admins.setChallenge(flow.id, challenge)) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已过期，请重试"), HttpStatusCode.BadRequest)
            return@post
        }
        call.respondRedirect("/admin/pending?flow_id=${flow.id}")
    }

    get("/admin/pending") {
        call.adminNoStore()
        val flow = admins.getFlow(call.request.queryParameters["flow_id"].orEmpty())
        if (flow == null) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已过期，请重试"), HttpStatusCode.BadRequest)
            return@get
        }
        val challenge = flow.challenge
        if (challenge == null) {
            call.respondAdminHtml(adminLoginPage(flow))
            return@get
        }
        val snapshot = try {
            authenticator.status(challenge)
        } catch (_: ChallengeError) {
            val retry = admins.resetChallenge(flow.id)
            if (retry == null) call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录已过期，请重新登录"), HttpStatusCode.Unauthorized)
            else call.respondAdminHtml(adminLoginPage(retry, "登录已过期，请重新登录"), HttpStatusCode.Unauthorized)
            return@get
        } catch (_: Exception) {
            call.respondAdminHtml(adminPendingPage(flow, "认证服务暂时不可用"), HttpStatusCode.ServiceUnavailable)
            return@get
        }
        when (snapshot["status"] as? String) {
            "authenticated" -> {
                val subject = authenticator.authenticatedSubject(challenge)
                val session = subject?.let { admins.createSession(flow.id, it) }
                if (session == null) {
                    subject?.let { audit?.record(it, "admin_login_denied") }
                    admins.resetChallenge(flow.id)
                    call.respondAdminHtml(adminLoginPage(admins.createFlow(), "该学工号没有管理工作台权限"), HttpStatusCode.Forbidden)
                } else {
                    audit?.record(session.studentId, "admin_login")
                    call.response.headers.append(HttpHeaders.SetCookie, adminCookie(session.token, config))
                    call.respondRedirect("/admin")
                }
            }
            "waiting_sms" -> call.respondAdminHtml(
                adminChallengePage(flow, "sms", "短信验证码", snapshot["masked_phone"] as? String ?: "", null),
            )
            "waiting_captcha" -> call.respondAdminHtml(
                adminChallengePage(flow, "captcha", "图形验证码", "", snapshot["captcha_image"] as? String),
            )
            "failed", "expired", "cancelled" -> {
                val retry = admins.resetChallenge(flow.id)
                if (retry == null) call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录失败，请检查学工号和密码"), HttpStatusCode.Unauthorized)
                else call.respondAdminHtml(adminLoginPage(retry, "登录失败，请检查学工号和密码"), HttpStatusCode.Unauthorized)
            }
            else -> call.respondAdminHtml(adminPendingPage(flow))
        }
    }

    post("/admin/continue") {
        call.adminNoStore()
        val params = call.receiveParameters()
        val flow = admins.getFlow(params["flow_id"].orEmpty())
        if (flow == null || !admins.hasValidCsrf(flow, params["csrf"].orEmpty())) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已过期，请重新登录"), HttpStatusCode.BadRequest)
            return@post
        }
        val challenge = flow.challenge
        if (challenge == null) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), "登录请求已过期，请重新登录"), HttpStatusCode.BadRequest)
            return@post
        }
        try {
            val answer = params["answer"].orEmpty()
            when (params["kind"]) {
                "sms" -> authenticator.submitSms(challenge, answer)
                "captcha" -> authenticator.submitCaptcha(challenge, answer)
                else -> {
                    call.respondAdminHtml(adminPendingPage(flow, "验证请求无效"), HttpStatusCode.BadRequest)
                    return@post
                }
            }
        } catch (_: Exception) {
            val snapshot = runCatching { authenticator.status(challenge) }.getOrNull().orEmpty()
            val kind = when (snapshot["status"]) {
                "waiting_sms" -> "sms"
                "waiting_captcha" -> "captcha"
                else -> null
            }
            if (kind == null) call.respondAdminHtml(adminPendingPage(flow, "正在重新检查认证状态"))
            else call.respondAdminHtml(
                adminChallengePage(
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
        call.respondRedirect("/admin/pending?flow_id=${flow.id}")
    }

    post("/admin/blocklist/add") {
        call.adminNoStore()
        val session = requireAdminSession(call, admins, config) ?: return@post
        val params = call.receiveParameters()
        if (!admins.hasValidCsrf(session, params["csrf"].orEmpty())) {
            call.respondAdminHtml(adminErrorPage("请求校验失败，请刷新页面后重试"), HttpStatusCode.Forbidden)
            return@post
        }
        val studentId = params["student_id"]?.trim().orEmpty()
        if (!OidcBlocklistStore.STUDENT_ID.matches(studentId)) {
            call.respondAdminHtml(
                adminDashboard(
                    session = session,
                    config = config,
                    entries = blocklist.list(),
                    runtimeStats = grants.runtimeStats(),
                    signingKey = signingKey,
                    auditEntries = audit?.list(12).orEmpty(),
                    auditCount = audit?.count() ?: 0,
                    message = "学工号格式无效",
                ),
                HttpStatusCode.BadRequest,
            )
            return@post
        }
        val added = blocklist.add(studentId)
        if (added) grants.revokeSubject(studentId)
        audit?.record(session.studentId, if (added) "blacklist_add" else "blacklist_add_existing", studentId)
        call.respondRedirect("/admin?status=${if (added) "added" else "exists"}")
    }

    post("/admin/blocklist/remove") {
        call.adminNoStore()
        val session = requireAdminSession(call, admins, config) ?: return@post
        val params = call.receiveParameters()
        if (!admins.hasValidCsrf(session, params["csrf"].orEmpty())) {
            call.respondAdminHtml(adminErrorPage("请求校验失败，请刷新页面后重试"), HttpStatusCode.Forbidden)
            return@post
        }
        val studentId = params["student_id"]?.trim().orEmpty()
        if (!OidcBlocklistStore.STUDENT_ID.matches(studentId)) {
            call.respondAdminHtml(
                adminDashboard(
                    session = session,
                    config = config,
                    entries = blocklist.list(),
                    runtimeStats = grants.runtimeStats(),
                    signingKey = signingKey,
                    auditEntries = audit?.list(12).orEmpty(),
                    auditCount = audit?.count() ?: 0,
                    message = "学工号格式无效",
                ),
                HttpStatusCode.BadRequest,
            )
            return@post
        }
        val removed = blocklist.remove(studentId)
        audit?.record(session.studentId, if (removed) "blacklist_remove" else "blacklist_remove_missing", studentId)
        call.respondRedirect("/admin?status=${if (removed) "removed" else "missing"}")
    }

    post("/admin/logout") {
        call.adminNoStore()
        val token = call.request.cookies[ADMIN_COOKIE]
        val session = admins.getSession(token) ?: run {
            call.expireAdminCookie(config)
            call.respondRedirect("/admin")
            return@post
        }
        val params = call.receiveParameters()
        if (!admins.hasValidCsrf(session, params["csrf"].orEmpty())) {
            call.respondAdminHtml(adminErrorPage("请求校验失败，请刷新页面后重试"), HttpStatusCode.Forbidden)
            return@post
        }
        audit?.record(session.studentId, "admin_logout")
        admins.revoke(token)
        call.expireAdminCookie(config)
        call.respondRedirect("/admin")
    }
}

private suspend fun requireAdminSession(call: ApplicationCall, admins: OidcAdminStore, config: OidcConfig): OidcAdminSession? {
    val session = admins.getSession(call.request.cookies[ADMIN_COOKIE])
    if (session == null) {
        call.expireAdminCookie(config)
        call.respondRedirect("/admin")
    }
    return session
}

private fun adminCookie(token: String, config: OidcConfig): String = buildString {
    append("$ADMIN_COOKIE=$token; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=${config.adminSessionTtlSeconds}")
    if (config.adminCookieSecure) append("; Secure")
}

private suspend fun ApplicationCall.expireAdminCookie(config: OidcConfig?) {
    val secure = if (config?.adminCookieSecure == true) "; Secure" else ""
    response.headers.append(HttpHeaders.SetCookie, "$ADMIN_COOKIE=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0$secure")
}

private fun queryMessage(status: String?): String? = when (status) {
    "added" -> "已加入黑名单"
    "exists" -> "该学工号已在黑名单中"
    "removed" -> "已从黑名单移除"
    "missing" -> "黑名单中没有该学工号"
    else -> null
}

private fun adminLoginPage(flow: OidcAdminFlow, error: String? = null): String = adminPage(
    title = "管理员登录",
    body = """
        <main class="login-shell">
          <div class="brand-mark">BIT<span>·</span>LOGIN</div>
          <p class="eyebrow">IDENTITY GATEWAY / ADMIN</p>
          <h1>管理工作台</h1>
          <p class="lede">使用已授权的管理员学工号登录</p>
          ${error?.let { "<p class=\"notice error\">${escapeHtml(it)}</p>" }.orEmpty()}
          <form method="post" action="/admin/login" class="login-form">
            ${hidden("flow_id", flow.id)}${hidden("csrf", flow.csrf)}
            <label for="username">学工号</label>
            <input id="username" name="username" autocomplete="username" maxlength="64" required autofocus>
            <label for="password">统一身份认证密码</label>
            <input id="password" name="password" type="password" autocomplete="current-password" maxlength="1024" required>
            <button class="button primary" type="submit">通过学校认证</button>
          </form>
          <p class="security-note">登录由学校统一身份认证验证；普通账号不会获得管理权限。</p>
        </main>
    """.trimIndent(),
)

private fun adminPendingPage(flow: OidcAdminFlow, message: String = "正在通过学校统一身份认证"): String = adminPage(
    title = "正在验证",
    head = "<meta http-equiv=\"refresh\" content=\"1;url=/admin/pending?flow_id=${flow.id}\">",
    body = "<main class=\"login-shell pending\"><div class=\"brand-mark\">BIT<span>·</span>LOGIN</div><p class=\"eyebrow\">ADMIN AUTHENTICATION</p><h1>${escapeHtml(message)}</h1><div class=\"progress-track\"><i></i></div></main>",
)

private fun adminChallengePage(
    flow: OidcAdminFlow,
    kind: String,
    label: String,
    maskedPhone: String,
    imageBase64: String?,
    error: String? = null,
): String {
    val image = if (kind == "captcha" && !imageBase64.isNullOrBlank()) {
        val bytes = runCatching { Base64.getDecoder().decode(imageBase64) }.getOrNull()
        val mime = if (bytes?.take(2) == listOf(0xff.toByte(), 0xd8.toByte())) "image/jpeg" else "image/png"
        "<img class=\"captcha\" src=\"data:$mime;base64,$imageBase64\" alt=\"验证码\">"
    } else ""
    return adminPage(
        title = "身份验证",
        body = """
            <main class="login-shell">
              <div class="brand-mark">BIT<span>·</span>LOGIN</div>
              <p class="eyebrow">ADMIN AUTHENTICATION</p>
              <h1>${escapeHtml(label)}</h1>
              ${if (maskedPhone.isNotBlank()) "<p class=\"lede\">${escapeHtml(maskedPhone)}</p>" else ""}
              $image
              ${error?.let { "<p class=\"notice error\">${escapeHtml(it)}</p>" }.orEmpty()}
              <form method="post" action="/admin/continue" class="login-form">
                ${hidden("flow_id", flow.id)}${hidden("csrf", flow.csrf)}${hidden("kind", kind)}
                <label for="answer">$label</label>
                <input id="answer" name="answer" autocomplete="one-time-code" maxlength="32" required autofocus>
                <button class="button primary" type="submit">确认</button>
              </form>
            </main>
        """.trimIndent(),
    )
}

private fun adminDashboard(
    session: OidcAdminSession,
    config: OidcConfig,
    entries: List<BlockedStudent>,
    runtimeStats: OidcRuntimeStats,
    signingKey: OidcSigningKey?,
    auditEntries: List<OidcAuditEntry>,
    auditCount: Long,
    message: String? = null,
): String {
    val rows = if (entries.isEmpty()) {
        "<tr><td class=\"empty\" colspan=\"3\">当前没有被限制的账号</td></tr>"
    } else entries.joinToString("") { entry ->
        """
        <tr>
          <td class="student-id">${escapeHtml(entry.studentId)}</td>
          <td class="date">${escapeHtml(formatTime(entry.createdAt))}</td>
          <td class="actions"><form method="post" action="/admin/blocklist/remove">
            ${hidden("csrf", session.csrf)}${hidden("student_id", entry.studentId)}
            <button class="button quiet" type="submit" aria-label="移除 ${escapeHtml(entry.studentId)}">移除</button>
          </form></td>
        </tr>
        """.trimIndent()
    }
    return adminPage(
        title = "身份网关工作台",
        body = """
          <header class="topbar">
            <div class="brand"><span class="brand-mark small">BIT<span>·</span>LOGIN</span><span class="divider"></span><span>身份网关 / 管理工作台</span></div>
            <div class="top-actions"><span class="identity"><i></i>${escapeHtml(session.studentId)}</span>
              <form method="post" action="/admin/logout">${hidden("csrf", session.csrf)}<button class="button logout" type="submit">退出</button></form>
            </div>
          </header>
          <main class="workspace">
            <div class="page-heading"><div><p class="eyebrow">IDENTITY OPERATIONS</p><h1>统一登录工作台</h1><p class="lede">BIT Login OIDC · 校内身份网关</p></div><span class="badge">校内试运行</span></div>
            <nav class="section-nav" aria-label="工作台导航"><a href="#overview">概览</a><a href="#application">应用接入</a><a href="#protocol">协议与安全</a><a href="#access">访问控制</a><a href="#audit">操作审计</a><a href="#migration">学校迁移</a></nav>
            ${message?.let { "<p class=\"notice\">${escapeHtml(it)}</p>" }.orEmpty()}
            ${workbenchOverview(config, runtimeStats, entries.size, auditCount)}
            ${workbenchApplication(config)}
            ${workbenchProtocol(config, signingKey)}
            <section id="access" class="add-section" aria-labelledby="add-title">
              <div class="section-heading"><div><p class="eyebrow">NEW RESTRICTION</p><h2 id="add-title">添加学工号</h2></div></div>
              <form method="post" action="/admin/blocklist/add" class="add-form">
                ${hidden("csrf", session.csrf)}
                <label class="sr-only" for="student-id">学工号</label>
                <input id="student-id" name="student_id" placeholder="输入学工号" autocomplete="off" maxlength="64" pattern="[A-Za-z0-9._-]{1,64}" required>
                <button class="button primary" type="submit"><span aria-hidden="true">+</span> 添加到黑名单</button>
              </form>
            </section>
            <section id="access-list" class="list-section" aria-labelledby="list-title">
              <div class="section-heading"><div><p class="eyebrow">CURRENT RULES</p><h2 id="list-title">受限账号</h2></div><span class="list-total">${entries.size} 条记录</span></div>
              <div class="table-wrap"><table><thead><tr><th scope="col">学工号</th><th scope="col">加入时间</th><th scope="col"><span class="sr-only">操作</span></th></tr></thead><tbody>$rows</tbody></table></div>
            </section>
            ${workbenchAudit(auditEntries, auditCount)}
            ${workbenchMigration(config)}
            <footer class="footnote">工作台配置来自服务启动参数；授权码、访问令牌和管理会话在服务重启后失效。</footer>
          </main>
        """.trimIndent(),
    )
}

private fun workbenchOverview(
    config: OidcConfig,
    runtimeStats: OidcRuntimeStats,
    blockedCount: Int,
    auditCount: Long,
): String = """
    <section id="overview" class="overview-section" aria-labelledby="overview-title">
      <div class="section-heading"><div><p class="eyebrow">SERVICE OVERVIEW</p><h2 id="overview-title">运行概览</h2></div><span class="origin">${escapeHtml(config.issuer)}</span></div>
      <div class="metric-grid">
        <div class="metric"><span>网关状态</span><strong class="live">在线</strong><small>身份认证服务可达</small></div>
        <div class="metric"><span>活跃登录</span><strong>${runtimeStats.activeLoginFlows}</strong><small>正在等待身份确认</small></div>
        <div class="metric"><span>访问令牌</span><strong>${runtimeStats.activeAccessTokens}</strong><small>内存中的有效令牌</small></div>
        <div class="metric"><span>受限账号</span><strong>${blockedCount}</strong><small>黑名单记录</small></div>
        <div class="metric"><span>审计记录</span><strong>${auditCount}</strong><small>管理员操作总数</small></div>
      </div>
    </section>
""".trimIndent()

private fun workbenchApplication(config: OidcConfig): String {
    val callbacks = config.redirectUris.sorted().joinToString("<br>") { "<code>${escapeHtml(it)}</code>" }
    val endpoints = listOf(
        "Discovery" to endpoint(config.issuer, "/.well-known/openid-configuration"),
        "Authorization" to endpoint(config.issuer, "/oauth/authorize"),
        "Token" to endpoint(config.issuer, "/oauth/token"),
        "UserInfo" to endpoint(config.issuer, "/oauth/userinfo"),
        "JWKS" to endpoint(config.issuer, "/jwks"),
    ).joinToString("") { (label, value) ->
        "<tr><th scope=\"row\">$label</th><td><code>${escapeHtml(value)}</code></td></tr>"
    }
    return """
    <section id="application" class="application-section" aria-labelledby="application-title">
      <div class="section-heading"><div><p class="eyebrow">REGISTERED APPLICATION</p><h2 id="application-title">应用接入</h2></div><span class="badge">单客户端模式</span></div>
      <div class="application-summary"><div><span class="eyebrow">CLIENT</span><h3>报销 OA</h3><code>${escapeHtml(config.clientId)}</code></div><div class="summary-status"><span class="status-dot"></span>已登记</div></div>
      <div class="detail-grid">
        <div class="detail-block"><span class="label">Issuer / 签发方</span><code>${escapeHtml(config.issuer)}</code></div>
        <div class="detail-block"><span class="label">Redirect URI / 回调地址</span><span>$callbacks</span></div>
      </div>
      <div class="table-wrap endpoint-table"><table><caption>对接端点</caption><tbody>$endpoints</tbody></table></div>
      <div class="section-actions"><span>导出的清单只包含公开接入参数，不含私钥、密码、令牌或数据库路径。</span><span class="download-actions"><a class="button secondary" href="/admin/export/oidc.md">下载申请清单</a><a class="button secondary" href="/admin/export/oidc.json">下载 JSON</a></span></div>
    </section>
""".trimIndent()
}

private fun workbenchProtocol(config: OidcConfig, signingKey: OidcSigningKey?): String {
    val keyDescription = signingKey?.let { "${it.algorithm} · ${it.keySizeBits} bit · kid ${it.keyId}" } ?: "RS256 · 2048 bit"
    return """
    <section id="protocol" class="protocol-section" aria-labelledby="protocol-title">
      <div class="section-heading"><div><p class="eyebrow">OIDC CONTRACT</p><h2 id="protocol-title">协议与安全</h2></div><span class="badge muted">只读配置</span></div>
      <div class="protocol-grid">
        <div class="protocol-item"><span class="label">授权流程</span><strong>Authorization Code</strong><small>浏览器登录后回调授权码</small></div>
        <div class="protocol-item"><span class="label">客户端安全</span><strong>PKCE · S256</strong><small>公开客户端，不使用 client secret</small></div>
        <div class="protocol-item"><span class="label">身份范围</span><strong>openid · student_id</strong><small>只返回学工号身份</small></div>
        <div class="protocol-item"><span class="label">令牌签名</span><strong>${escapeHtml(keyDescription)}</strong><small>公钥通过 JWKS 发布</small></div>
      </div>
      <div class="claims-line"><span class="label">当前 Claims</span><code>sub</code><code>student_id</code><span class="claim-note">不包含姓名、成绩、课表等业务信息</span></div>
    </section>
""".trimIndent()
}

private fun workbenchAudit(entries: List<OidcAuditEntry>, total: Long): String {
    val rows = if (entries.isEmpty()) {
        "<tr><td class=\"empty\" colspan=\"4\">暂时没有管理员操作记录</td></tr>"
    } else entries.joinToString("") { entry ->
        val target = entry.targetStudentId.takeIf(String::isNotBlank)?.let { "<code>${escapeHtml(it)}</code>" } ?: "—"
        "<tr><td>${escapeHtml(formatTime(entry.createdAt))}</td><td><code>${escapeHtml(entry.actorStudentId)}</code></td><td>${escapeHtml(auditLabel(entry.action))}</td><td>$target</td></tr>"
    }
    return """
    <section id="audit" class="audit-section" aria-labelledby="audit-title">
      <div class="section-heading"><div><p class="eyebrow">ADMIN ACTIVITY</p><h2 id="audit-title">操作审计</h2></div><span class="list-total">最近 ${entries.size} 条 / 共 $total 条</span></div>
      <div class="table-wrap"><table><thead><tr><th scope="col">时间</th><th scope="col">管理员</th><th scope="col">动作</th><th scope="col">对象</th></tr></thead><tbody>$rows</tbody></table></div>
      <p class="section-note">只记录管理员学工号、动作和目标学工号；不记录密码、验证码、授权码或访问令牌。</p>
    </section>
""".trimIndent()
}

private fun workbenchMigration(config: OidcConfig): String = """
    <section id="migration" class="migration-section" aria-labelledby="migration-title">
      <div class="section-heading"><div><p class="eyebrow">SCHOOL MIGRATION BRIEF</p><h2 id="migration-title">学校迁移申请</h2></div><span class="badge muted">可导出</span></div>
      <div class="migration-grid">
        <div><h3>申请时可提供</h3><ul><li>OIDC Issuer、Discovery、授权、令牌、UserInfo 和 JWKS 端点</li><li>客户端 ID：<code>${escapeHtml(config.clientId)}</code></li><li>精确回调地址、Authorization Code、PKCE S256、开放范围和 Claims</li></ul></div>
        <div><h3>迁移边界</h3><ul><li>当前下游协议保持 OIDC identity-only，不接入业务数据</li><li>学校统一登录替换的是服务端上游认证适配层</li><li>Issuer、回调地址和 TLS 变更仍由部署配置与重启完成</li></ul></div>
      </div>
      <p class="migration-note">当前地址是校内 HTTP 试运行地址。正式迁移时应使用学校批准的 HTTPS 域名或校园 PKI 证书，并重新登记精确回调地址。</p>
    </section>
""".trimIndent()

private fun endpoint(issuer: String, path: String): String = issuer.trimEnd('/') + path

private fun auditLabel(action: String): String = when (action) {
    "admin_login" -> "管理员登录"
    "admin_login_denied" -> "登录被拒"
    "admin_logout" -> "退出工作台"
    "blacklist_add" -> "加入黑名单"
    "blacklist_add_existing" -> "重复加入黑名单"
    "blacklist_remove" -> "移出黑名单"
    "blacklist_remove_missing" -> "移除不存在账号"
    else -> action
}

private fun oidcIntegrationJson(config: OidcConfig, signingKey: OidcSigningKey?): JsonObject = buildJsonObject {
    put("issuer", config.issuer)
    put("client_id", config.clientId)
    put("redirect_uris", JsonArray(config.redirectUris.sorted().map(::JsonPrimitive)))
    put("response_type", "code")
    put("grant_type", "authorization_code")
    put("pkce", "S256")
    put("token_endpoint_auth_method", "none")
    put("scopes", JsonArray(listOf(JsonPrimitive("openid"), JsonPrimitive("student_id"))))
    put("claims", JsonArray(listOf(JsonPrimitive("sub"), JsonPrimitive("student_id"))))
    put("tls_required_for_production", true)
    put("endpoints", buildJsonObject {
        put("discovery", endpoint(config.issuer, "/.well-known/openid-configuration"))
        put("authorization", endpoint(config.issuer, "/oauth/authorize"))
        put("token", endpoint(config.issuer, "/oauth/token"))
        put("userinfo", endpoint(config.issuer, "/oauth/userinfo"))
        put("jwks", endpoint(config.issuer, "/jwks"))
    })
    put("signing", buildJsonObject {
        put("algorithm", signingKey?.algorithm ?: "RS256")
        put("key_id", signingKey?.keyId ?: "oidc-1")
        put("public_key_endpoint", endpoint(config.issuer, "/jwks"))
    })
}

private fun oidcIntegrationMarkdown(config: OidcConfig, signingKey: OidcSigningKey?): String = buildString {
    appendLine("# BIT Login OIDC 统一登录接入清单")
    appendLine()
    appendLine("> 此清单用于学校统一登录申请和下游应用登记；不包含私钥、密码、令牌或数据库信息。")
    appendLine()
    appendLine("## 应用登记")
    appendLine()
    appendLine("- Issuer：`${config.issuer}`")
    appendLine("- Client ID：`${config.clientId}`")
    appendLine("- Response type：`code`")
    appendLine("- Grant type：`authorization_code`")
    appendLine("- Client authentication：`none`（公开客户端）")
    appendLine("- PKCE：`S256`")
    appendLine("- Scopes：`openid student_id`")
    appendLine("- Claims：`sub`、`student_id`")
    appendLine()
    appendLine("### 精确回调地址")
    config.redirectUris.sorted().forEach { appendLine("- `$it`") }
    appendLine()
    appendLine("## OIDC 端点")
    appendLine()
    appendLine("| 用途 | 地址 |")
    appendLine("| --- | --- |")
    appendLine("| Discovery | `${endpoint(config.issuer, "/.well-known/openid-configuration")}` |")
    appendLine("| Authorization | `${endpoint(config.issuer, "/oauth/authorize")}` |")
    appendLine("| Token | `${endpoint(config.issuer, "/oauth/token")}` |")
    appendLine("| UserInfo | `${endpoint(config.issuer, "/oauth/userinfo")}` |")
    appendLine("| JWKS | `${endpoint(config.issuer, "/jwks")}` |")
    appendLine()
    appendLine("## 签名与迁移说明")
    appendLine()
    appendLine("- ID Token 签名：`${signingKey?.algorithm ?: "RS256"}`，kid：`${signingKey?.keyId ?: "oidc-1"}`。公钥通过 JWKS 发布。")
    appendLine("- 当前服务只返回学工号身份，不返回姓名、成绩、课表等业务数据。")
    appendLine("- 当前地址仅适合校内 HTTP 试运行；正式部署应使用学校批准的 HTTPS 域名或校园 PKI 证书。")
    appendLine("- 学校迁移时保留下游 OIDC 合约，替换服务端上游认证适配层，并重新登记精确 Issuer 和回调地址。")
}

private fun adminErrorPage(message: String): String = adminPage(
    title = "请求无效",
    body = "<main class=\"login-shell\"><p class=\"eyebrow\">REQUEST REJECTED</p><h1>${escapeHtml(message)}</h1><a class=\"back-link\" href=\"/admin\">返回工作台</a></main>",
)

private fun formatTime(epochSeconds: Long): String = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
    .withZone(ZoneId.systemDefault())
    .format(Instant.ofEpochSecond(epochSeconds))

private fun hidden(name: String, value: String): String =
    "<input type=\"hidden\" name=\"$name\" value=\"${escapeHtml(value)}\">"

private fun escapeHtml(value: String): String = value
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace("\"", "&quot;")
    .replace("'", "&#39;")

private fun adminPage(title: String, body: String, head: String = ""): String = """
    <!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)} · BIT Login</title>$head<style>
    button{font-family:inherit;font-size:13px;font-weight:600}
    :root{color-scheme:light;--ink:#1b2926;--muted:#62716d;--line:#dce4e1;--paper:#fff;--wash:#f3f6f4;--green:#176b54;--green-dark:#105541;--coral:#b6483f;--mint:#dff1e9;font-family:"Aptos","Microsoft YaHei UI",sans-serif;color:var(--ink);background:var(--wash)}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--wash)}.topbar{height:64px;background:#182824;color:#eef5f1;display:flex;align-items:center;justify-content:space-between;padding:0 max(28px,calc((100vw - 1120px)/2));border-bottom:3px solid #50a383}.brand,.top-actions{display:flex;align-items:center;gap:16px;font-size:13px}.brand-mark{font-family:Georgia,serif;font-size:13px;font-weight:700;letter-spacing:1px;color:#245b49}.brand-mark span{color:#cc765d;margin:0 2px}.brand-mark.small{color:#eef5f1;font-size:12px}.divider{height:20px;border-left:1px solid #53635e}.identity{display:flex;align-items:center;gap:8px;color:#d9e6e0}.identity i,.status-dot{width:8px;height:8px;border-radius:50%;background:#71c49e;display:inline-block}.workspace{width:min(100% - 40px,1000px);margin:0 auto;padding:48px 0 36px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;padding:0 0 30px;border-bottom:1px solid var(--line)}.eyebrow{font-size:10px;font-weight:700;letter-spacing:1.4px;color:#687973;margin:0 0 10px}h1,h2,p{margin-top:0}h1{font-family:Georgia,"Microsoft YaHei UI",serif;font-size:31px;line-height:1.2;font-weight:600;margin-bottom:8px}h2{font-size:17px;margin:0;font-weight:650}.lede{font-size:14px;color:var(--muted);margin:0}.count{display:flex;align-items:baseline;gap:9px;padding:0 2px 3px}.count strong{font-family:Georgia,serif;font-size:32px;font-weight:500;color:var(--green)}.count span,.list-total{font-size:12px;color:var(--muted)}.add-section,.list-section{padding:27px 0;border-bottom:1px solid var(--line)}.section-heading{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:17px}.section-heading .eyebrow{margin-bottom:6px}.add-form{display:flex;gap:10px;max-width:610px}.add-form input,.login-form input{min-width:0;height:42px;border:1px solid #b9c8c1;border-radius:3px;background:#fff;padding:0 12px;color:var(--ink);font-size:14px}.add-form input{flex:1}.add-form input:focus,.login-form input:focus{outline:2px solid #abd8c4;outline-offset:1px;border-color:var(--green)}.button{min-height:38px;border:1px solid transparent;border-radius:3px;padding:0 15px;font:600 13px inherit;cursor:pointer}.button.primary{background:var(--green);color:#fff}.button.primary:hover{background:var(--green-dark)}.add-form .button{height:42px}.add-form .button span{font-size:18px;vertical-align:-1px;margin-right:5px}.button.quiet{min-height:30px;padding:0 10px;background:#fff;border-color:#cbd6d1;color:#52645d}.button.quiet:hover{border-color:var(--coral);color:var(--coral)}.button.logout{min-height:30px;background:transparent;border-color:#62736d;color:#eef5f1;padding:0 11px}.button.logout:hover{background:#2d4139}.top-actions form,.actions form{margin:0}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;text-align:left;font-size:13px}th{font-size:10px;font-weight:700;letter-spacing:.6px;color:#74827d;background:#e9efec;padding:11px 14px}td{padding:11px 14px;border-bottom:1px solid #e7ece9}tbody tr:last-child td{border-bottom:0}.student-id{font-variant-numeric:tabular-nums;font-weight:650}.date{color:var(--muted);font-variant-numeric:tabular-nums}.actions{text-align:right;width:100px}.empty{text-align:center;color:#75837e;padding:34px 12px}.footnote{display:flex;align-items:center;gap:9px;padding-top:22px;font-size:12px;color:var(--muted)}.footnote .status-dot{width:7px;height:7px;flex:none}.notice{margin:16px 0 0;padding:10px 12px;border-left:3px solid var(--green);background:#e9f3ee;color:#31594a;font-size:13px}.notice.error{border-color:var(--coral);background:#fbefed;color:#963e38}.login-shell{width:min(100% - 32px,440px);margin:9vh auto;padding:34px 36px 30px;background:var(--paper);border:1px solid var(--line);border-top:4px solid var(--green);box-shadow:0 10px 30px #1b29260b}.login-shell .brand-mark{margin-bottom:36px}.login-shell h1{font-size:27px}.login-shell .eyebrow{margin-bottom:8px}.login-shell .lede{margin-bottom:22px}.login-form{display:grid;gap:9px}.login-form label{margin-top:8px;font-size:12px;font-weight:650;color:#42524c}.login-form input{width:100%;height:44px}.login-form .button{height:44px;margin-top:10px}.security-note{font-size:11px;color:#718079;border-top:1px solid var(--line);padding-top:16px;margin:24px 0 0}.pending{margin-top:18vh}.progress-track{height:3px;background:#e7efeb;margin-top:28px;overflow:hidden}.progress-track i{display:block;width:42%;height:100%;background:#368565;animation:progress 1.2s ease-in-out infinite alternate}@keyframes progress{to{transform:translateX(130%)}}.captcha{display:block;max-width:100%;height:auto;margin:14px 0}.back-link{color:var(--green)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
    @media(max-width:620px){.topbar{height:auto;min-height:60px;padding:12px 16px}.brand{gap:9px;font-size:11px}.brand-mark.small{font-size:10px}.top-actions{gap:8px}.identity{font-size:11px}.workspace{width:calc(100% - 32px);padding-top:30px}.page-heading{align-items:flex-start}.page-heading h1{font-size:27px}.count{gap:5px;flex-direction:column}.count strong{font-size:27px}.add-form{flex-direction:column}.add-form input,.add-form .button{width:100%;flex:none}.section-heading{align-items:center}.list-total{font-size:11px}.login-shell{padding:28px 22px}.footnote{align-items:flex-start;line-height:1.5}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}
    ${workbenchStyles()}
    </style></head><body>$body</body></html>
""".trimIndent()

private fun workbenchStyles(): String = """
    .badge{display:inline-flex;align-items:center;min-height:26px;padding:0 10px;border:1px solid #a8cdbd;border-radius:999px;background:#edf7f1;color:#216348;font-size:11px;font-weight:700;letter-spacing:.3px}.badge.muted{border-color:#d1dcd7;background:#f4f7f5;color:#667770;font-weight:600}
    .section-nav{display:flex;gap:18px;overflow-x:auto;padding:14px 0;border-bottom:1px solid var(--line);white-space:nowrap}.section-nav a{color:#51645c;text-decoration:none;font-size:12px;font-weight:650}.section-nav a:hover{color:var(--green);text-decoration:underline;text-underline-offset:4px}
    .origin{max-width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#6d7d76;font:12px ui-monospace,SFMono-Regular,Consolas,monospace}.overview-section,.application-section,.protocol-section,.audit-section,.migration-section{padding:27px 0;border-bottom:1px solid var(--line)}
    .metric-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));border:1px solid var(--line);background:var(--paper)}.metric{min-height:112px;padding:17px 16px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span,.metric small{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;margin:10px 0 6px;color:var(--green);font:500 25px Georgia,serif}.metric strong.live{font:650 18px "Aptos","Microsoft YaHei UI",sans-serif;color:#24704f}.metric small{font-size:10px;color:#829089}
    .application-summary{display:flex;align-items:center;justify-content:space-between;padding:18px 0;border-bottom:1px solid var(--line)}.application-summary h3{margin:0 0 6px;font:600 22px Georgia,"Microsoft YaHei UI",serif}.application-summary code{font-size:12px;color:#4b645b}.summary-status{display:flex;align-items:center;gap:8px;color:#287052;font-size:12px;font-weight:650}.summary-status .status-dot{width:8px;height:8px}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:20px 0}.detail-block{display:grid;gap:8px;min-width:0}.detail-block code{overflow-wrap:anywhere}.label{display:block;color:#73827c;font-size:10px;font-weight:700;letter-spacing:.6px;text-transform:uppercase}.endpoint-table{border-top:1px solid var(--line)}.endpoint-table caption{text-align:left;padding:18px 0 10px;color:#73827c;font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase}.endpoint-table th{width:150px;background:transparent;padding-left:0;color:#64756e;text-transform:none;letter-spacing:0}.endpoint-table td{padding-left:0}.endpoint-table code{overflow-wrap:anywhere;font-size:12px}.section-actions{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:18px;color:#74837d;font-size:11px}.download-actions{display:flex;gap:8px;flex:none}.button.secondary{display:inline-flex;align-items:center;justify-content:center;min-height:34px;background:#fff;border-color:#a9bbb3;color:#315b4c;text-decoration:none}.button.secondary:hover{border-color:var(--green);background:#f0f8f3}
    .protocol-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid var(--line);background:var(--paper)}.protocol-item{min-height:108px;padding:16px;border-right:1px solid var(--line)}.protocol-item:last-child{border-right:0}.protocol-item strong{display:block;margin:10px 0 5px;font-size:14px;color:var(--ink)}.protocol-item small{display:block;color:#7b8983;font-size:11px;line-height:1.45}.claims-line{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:17px 0 0}.claims-line code{padding:4px 7px;border:1px solid #c9d9d0;background:#f1f7f3;color:#28634c;font-size:11px}.claim-note{color:#7b8983;font-size:11px}
    .audit-section .table-wrap{border-top:1px solid var(--line)}.audit-section table{font-size:12px}.audit-section th{background:transparent;padding-left:0}.audit-section td{padding-left:0}.audit-section td code{font-size:11px}.section-note,.migration-note{margin:14px 0 0;color:#7b8983;font-size:11px}.migration-grid{display:grid;grid-template-columns:1fr 1fr;gap:28px}.migration-grid h3{margin:0 0 11px;font-size:14px}.migration-grid ul{margin:0;padding-left:18px;color:#63736c;font-size:12px;line-height:1.8}.migration-grid code{font-size:11px;color:#315f4c}.migration-note{padding:11px 12px;border-left:3px solid #cf9b6e;background:#fbf5ee;color:#765f49}
    @media(max-width:760px){.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.metric:nth-child(2n){border-right:0}.metric:nth-child(n+3){border-top:1px solid var(--line)}.protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.protocol-item:nth-child(2n){border-right:0}.protocol-item:nth-child(n+3){border-top:1px solid var(--line)}.section-actions{align-items:flex-start;flex-direction:column}.download-actions{width:100%}.download-actions .button{flex:1}.origin{max-width:40%}}
    @media(max-width:520px){.page-heading{gap:12px}.page-heading .badge{flex:none}.detail-grid,.migration-grid{grid-template-columns:1fr;gap:14px}.application-summary{align-items:flex-start;gap:12px;flex-direction:column}.endpoint-table th{width:105px}.protocol-grid{grid-template-columns:1fr}.protocol-item{border-right:0;border-bottom:1px solid var(--line)}.protocol-item:last-child{border-bottom:0}.metric-grid{grid-template-columns:1fr 1fr}.metric{padding:14px 12px}.section-nav{gap:14px}}
""".trimIndent()

private suspend fun ApplicationCall.adminNoStore() {
    response.headers.append(HttpHeaders.CacheControl, "no-store, no-cache, max-age=0")
    response.headers.append(HttpHeaders.Pragma, "no-cache")
    response.headers.append("Referrer-Policy", "no-referrer")
    response.headers.append("X-Content-Type-Options", "nosniff")
    response.headers.append("X-Frame-Options", "DENY")
    response.headers.append("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

private suspend fun ApplicationCall.respondAdminHtml(value: String, status: HttpStatusCode = HttpStatusCode.OK) {
    adminNoStore()
    respondText(value, ContentType.parse("text/html; charset=utf-8"), status)
}

private val ADMIN_COOKIE = "bit_oidc_admin"
