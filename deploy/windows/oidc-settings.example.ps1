$OidcSettings = @{
    Host                  = '127.0.0.1'
    Port                  = 16384
    Issuer                = 'https://login.example.edu'
    ClientId              = 'example-app'
    RedirectUris          = @('https://app.example.edu/oidc/callback')
    AdminStudentIds       = @()
    AdminSessionTtlSeconds = 1800
    AdminCookieSecure     = $true
}
