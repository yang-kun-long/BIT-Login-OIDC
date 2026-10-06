$OidcSettings = @{
    Host                  = '127.0.0.1'
    Port                  = 16384
    Issuer                = 'https://login.example.edu'
    ClientId              = 'example-app'
    RedirectUris          = @('https://app.example.edu/oidc/callback')
    UpstreamCallbackUrl   = 'https://sso.bit.edu.cn/gate/cas-success/personal-center-home-page?personId=667e67ca6b050d065ecbf781&pageId=666fffd2397df800012e5a4c&objectId=6889cb58bbce4700065c13b7'
    UpstreamClientId      = 'OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w'
    AdminStudentIds       = @()
    AdminSessionTtlSeconds = 1800
    AdminCookieSecure     = $true
}
