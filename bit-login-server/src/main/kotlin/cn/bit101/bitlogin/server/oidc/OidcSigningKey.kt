package cn.bit101.bitlogin.server.oidc

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

class OidcSigningKey private constructor(private val key: RSAKey) {
    fun sign(claims: JWTClaimsSet): String {
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.keyID)
                .type(JOSEObjectType.JWT)
                .build(),
            claims,
        )
        jwt.sign(RSASSASigner(key))
        return jwt.serialize()
    }

    fun jwks(): JsonObject = Json.parseToJsonElement(JWKSet(key.toPublicJWK()).toString()).jsonObject

    companion object {
        fun loadOrCreate(fileName: String, keyId: String): OidcSigningKey {
            val path = Paths.get(fileName).toAbsolutePath()
            Files.createDirectories(path.parent)
            if (!Files.exists(path)) createKey(path, keyId)
            val body = Files.readString(path)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
            val encoded = Base64.getMimeDecoder().decode(body)
            val privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(encoded)) as? RSAPrivateCrtKey
                ?: error("OIDC signing key must be an RSA PKCS#8 private key")
            require(privateKey.modulus.bitLength() >= 2048) { "OIDC RSA signing keys must be at least 2048 bits" }
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(
                RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent),
            ) as RSAPublicKey
            return OidcSigningKey(
                RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .build(),
            )
        }

        private fun createKey(path: Path, keyId: String) {
            val generated = try {
                RSAKeyGenerator(2048).keyID(keyId).generate()
            } catch (e: JOSEException) {
                throw IllegalStateException("Could not generate OIDC signing key", e)
            }
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(generated.toPrivateKey().encoded)
            val pem = "-----BEGIN PRIVATE KEY-----\n$encoded\n-----END PRIVATE KEY-----\n"
            Files.writeString(path, pem)
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            } catch (_: UnsupportedOperationException) {
                // Windows ACLs are set by the deployment script.
            }
        }
    }
}
