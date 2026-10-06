# 腾讯云 Linux 部署

统一登录网关部署到 `/opt/bit-login-oidc`，服务仅监听 `127.0.0.1:16384`，由 Nginx 在 `9443` 终止 TLS。报销 OA 继续使用 `443`，其 OIDC issuer 配置为：

```text
https://81.70.17.186:9443
```

创建专用用户和目录后，将 `bit-login-server` 的 `installDist` 产物解压到 `/opt/bit-login-oidc/app`，将本目录的 systemd/Nginx 配置分别安装到 `/etc/systemd/system/` 和 `/etc/nginx/sites-enabled/`。环境文件权限设为 `600`，至少包含：

```dotenv
HOST=127.0.0.1
PORT=16384
IDENTITY_ONLY=true
BASE_URL=https://81.70.17.186:9443
AUTH_DB_PATH=/var/lib/bit-login-oidc/auth.db
OIDC_ISSUER=https://81.70.17.186:9443
OIDC_APPLICATIONS=[{"client_id":"reimbursement-oa","name":"报销 OA","redirect_uris":["https://81.70.17.186/api/auth/oidc/callback"],"access_token_ttl_seconds":604800}]
OIDC_SIGNING_KEY_FILE=/var/lib/bit-login-oidc/oidc-signing-key.pem
OIDC_UPSTREAM_CALLBACK_URL=https://sso.bit.edu.cn/gate/cas-success/personal-center-home-page?personId=667e67ca6b050d065ecbf781&pageId=666fffd2397df800012e5a4c&objectId=6889cb58bbce4700065c13b7
OIDC_UPSTREAM_CLIENT_ID=OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w
```

应用 token 有效期由统一登录网关签发；每个应用可在 `OIDC_APPLICATIONS` 中单独填写秒数，默认 604800 秒（7 天）。OA 自身的会话有效期由 OA `.env` 的 `SESSION_TTL_SECONDS` 控制，默认同为 7 天。
