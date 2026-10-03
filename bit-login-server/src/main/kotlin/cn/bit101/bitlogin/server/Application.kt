package cn.bit101.bitlogin.server

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopping
import io.ktor.server.application.ApplicationStopped
import io.ktor.server.application.application
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.routing.routing
import kotlinx.coroutines.launch
import cn.bit101.bitlogin.server.auth.AuthWorker
import cn.bit101.bitlogin.server.auth.ChallengeStore
import cn.bit101.bitlogin.server.config.AppConfig
import cn.bit101.bitlogin.server.oidc.CasIdentityAuthenticator
import cn.bit101.bitlogin.server.oidc.OidcConfig
import cn.bit101.bitlogin.server.oidc.OidcGrantStore
import cn.bit101.bitlogin.server.oidc.OidcAdminStore
import cn.bit101.bitlogin.server.oidc.OidcAuditStore
import cn.bit101.bitlogin.server.oidc.OidcBlocklistStore
import cn.bit101.bitlogin.server.oidc.OidcSigningKey
import cn.bit101.bitlogin.server.oidc.oidcAdminRoutes
import cn.bit101.bitlogin.server.oidc.oidcRoutes
import cn.bit101.bitlogin.server.ics.IcsFileStore
import cn.bit101.bitlogin.server.plugins.configureCors
import cn.bit101.bitlogin.server.plugins.configureLogging
import cn.bit101.bitlogin.server.plugins.configureSerialization
import cn.bit101.bitlogin.server.plugins.configureStatusPages
import cn.bit101.bitlogin.server.routes.authRoutes
import cn.bit101.bitlogin.server.routes.cookieRoutes
import cn.bit101.bitlogin.server.routes.icsRoutes
import cn.bit101.bitlogin.server.routes.jwbRoutes
import cn.bit101.bitlogin.server.routes.jxzxehallRoutes
import cn.bit101.bitlogin.server.routes.rootRoute
import cn.bit101.bitlogin.server.service.AuthServiceExecutor

fun main() {
    val config = AppConfig.fromEnv()
    embeddedServer(Netty, port = config.port, host = config.host) {
        mainModule(config, OidcConfig.fromEnv())
    }.start(wait = true)
}

fun Application.mainModule(appConfig: AppConfig, oidcConfig: OidcConfig = OidcConfig.fromEnv()): ChallengeStore {
    val challengeStore = ChallengeStore(
        database = appConfig.authDbPath,
        pendingTtl = appConfig.authChallengeTtl,
        readyTtl = appConfig.authSessionTtl,
    )
    val closeChallengeStore = { challengeStore.close() }
    monitor.subscribe(ApplicationStopping) { closeChallengeStore() }
    monitor.subscribe(ApplicationStopped) { closeChallengeStore() }
    configureSerialization()
    configureStatusPages()
    if (!appConfig.identityOnly) {
        configureLogging()
        configureCors(appConfig)
    }

    if (appConfig.identityOnly) {
        val grants = OidcGrantStore(oidcConfig)
        val blocklist = OidcBlocklistStore(appConfig.authDbPath)
        val audit = OidcAuditStore(appConfig.authDbPath)
        monitor.subscribe(ApplicationStopping) { audit.close() }
        monitor.subscribe(ApplicationStopped) { audit.close() }
        val admins = oidcConfig.adminStudentIds.takeIf { it.isNotEmpty() }
            ?.let { OidcAdminStore(it, oidcConfig.adminSessionTtlSeconds) }
        val signingKey = OidcSigningKey.loadOrCreate(oidcConfig.signingKeyFile, oidcConfig.keyId)
        val authenticator = CasIdentityAuthenticator(
            challengeStore,
            connectTimeoutMs = appConfig.connectTimeoutMs,
            socketTimeoutMs = appConfig.socketTimeoutMs,
        )
        routing {
            rootRoute(identityOnly = true)
            oidcRoutes(oidcConfig, signingKey, grants, authenticator, blocklist)
            if (admins != null) oidcAdminRoutes(oidcConfig, admins, blocklist, grants, authenticator, signingKey, audit)
        }
        launch {
            while (true) {
                kotlinx.coroutines.delay(60_000)
                challengeStore.cleanup()
                grants.cleanup()
                admins?.cleanup()
            }
        }
        return challengeStore
    }

    val icsStore = IcsFileStore(baseUrl = appConfig.baseUrl)
    val authWorker = AuthWorker(
        challengeStore,
        connectTimeoutMs = appConfig.connectTimeoutMs,
        socketTimeoutMs = appConfig.socketTimeoutMs,
    )
    val authExecutor = AuthServiceExecutor(challengeStore, authWorker)
    routing {
        rootRoute()
        authRoutes(authWorker, challengeStore)
        jwbRoutes(authExecutor)
        jxzxehallRoutes(authExecutor, icsStore)
        cookieRoutes(authExecutor)
        icsRoutes(icsStore)
    }

    // Background cleanup
    launch { icsStore.cleanupLoop() }
    launch {
        while (true) {
            kotlinx.coroutines.delay(60_000)
            challengeStore.cleanup()
        }
    }
    return challengeStore
}

