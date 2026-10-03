package cn.bit101.bitlogin.server.routes

import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

fun Routing.rootRoute(identityOnly: Boolean = false) {
    get("/") {
        call.respond(
            JsonObject(
                mapOf("message" to JsonPrimitive(if (identityOnly) "BIT OIDC identity provider is running" else "BIT Login Services API is running")),
            ),
        )
    }
}
