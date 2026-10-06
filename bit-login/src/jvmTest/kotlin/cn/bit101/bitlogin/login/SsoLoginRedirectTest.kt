package cn.bit101.bitlogin.login

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SsoLoginRedirectTest {

    @Test
    fun `same-host http redirect is upgraded and port 80 is removed`() {
        assertEquals(
            "https://sso.bit.edu.cn/cas/oauth2.0/authorize?code=1",
            upgradeSameHostHttpRedirect(
                "http://sso.bit.edu.cn:80/cas/oauth2.0/authorize?code=1",
                "sso.bit.edu.cn",
            ),
        )
    }

    @Test
    fun `cross-host and non-http redirects are left unchanged`() {
        assertEquals(
            "http://other.example.test/callback",
            upgradeSameHostHttpRedirect("http://other.example.test/callback", "sso.bit.edu.cn"),
        )
        assertEquals(
            "https://sso.bit.edu.cn/callback",
            upgradeSameHostHttpRedirect("https://sso.bit.edu.cn/callback", "sso.bit.edu.cn"),
        )
    }
}
