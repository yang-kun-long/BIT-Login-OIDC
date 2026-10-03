package cn.bit101.bitlogin.server.oidc

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Base64
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import cn.bit101.bitlogin.server.auth.ChallengeError

fun Route.oidcAdminRoutes(
    config: OidcConfig,
    admins: OidcAdminStore,
    blocklist: OidcBlocklistStore,
    grants: OidcGrantStore,
    authenticator: IdentityAuthenticator,
) {
    get("/admin") {
        call.adminNoStore()
        val session = admins.getSession(call.request.cookies[ADMIN_COOKIE])
        if (session == null) {
            call.respondAdminHtml(adminLoginPage(admins.createFlow(), queryMessage(call.request.queryParameters["status"])))
        } else {
            call.respondAdminHtml(adminDashboard(session, blocklist.list(), queryMessage(call.request.queryParameters["status"])))
        }
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
                    admins.resetChallenge(flow.id)
                    call.respondAdminHtml(adminLoginPage(admins.createFlow(), "该学工号没有管理工作台权限"), HttpStatusCode.Forbidden)
                } else {
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
            call.respondAdminHtml(adminDashboard(session, blocklist.list(), "学工号格式无效"), HttpStatusCode.BadRequest)
            return@post
        }
        val added = blocklist.add(studentId)
        if (added) grants.revokeSubject(studentId)
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
            call.respondAdminHtml(adminDashboard(session, blocklist.list(), "学工号格式无效"), HttpStatusCode.BadRequest)
            return@post
        }
        val removed = blocklist.remove(studentId)
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

private fun adminDashboard(session: OidcAdminSession, entries: List<BlockedStudent>, message: String? = null): String {
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
            <div class="page-heading"><div><p class="eyebrow">ACCESS CONTROL</p><h1>账号黑名单</h1><p class="lede">限制指定学工号通过此身份网关完成认证。</p></div><div class="count"><strong>${entries.size}</strong><span>受限账号</span></div></div>
            ${message?.let { "<p class=\"notice\">${escapeHtml(it)}</p>" }.orEmpty()}
            <section class="add-section" aria-labelledby="add-title">
              <div class="section-heading"><div><p class="eyebrow">NEW RESTRICTION</p><h2 id="add-title">添加学工号</h2></div></div>
              <form method="post" action="/admin/blocklist/add" class="add-form">
                ${hidden("csrf", session.csrf)}
                <label class="sr-only" for="student-id">学工号</label>
                <input id="student-id" name="student_id" placeholder="输入学工号" autocomplete="off" maxlength="64" pattern="[A-Za-z0-9._-]{1,64}" required>
                <button class="button primary" type="submit"><span aria-hidden="true">+</span> 添加到黑名单</button>
              </form>
            </section>
            <section class="list-section" aria-labelledby="list-title">
              <div class="section-heading"><div><p class="eyebrow">CURRENT RULES</p><h2 id="list-title">受限账号</h2></div><span class="list-total">${entries.size} 条记录</span></div>
              <div class="table-wrap"><table><thead><tr><th scope="col">学工号</th><th scope="col">加入时间</th><th scope="col"><span class="sr-only">操作</span></th></tr></thead><tbody>$rows</tbody></table></div>
            </section>
            <footer class="footnote"><span class="status-dot"></span>身份认证仅返回学工号。黑名单在 CAS 登录完成、令牌兑换和用户信息查询时生效。</footer>
          </main>
        """.trimIndent(),
    )
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
    </style></head><body>$body</body></html>
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
