#!/usr/bin/env bash
set -euo pipefail

root=/opt/bit-login-oidc
data=/var/lib/bit-login-oidc
conf=/etc/bit-login-oidc

id bitlogin >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin bitlogin
install -d -o bitlogin -g bitlogin -m 0750 "$root" "$data"
install -d -o root -g bitlogin -m 0750 "$conf"
rm -rf "$root/app.new"
cp -a /home/ubuntu/bit-login-build/bit-login-server/build/install/bit-login-server "$root/app.new"
chown -R bitlogin:bitlogin "$root/app.new"
rm -rf "$root/app.old"
if [ -d "$root/app" ]; then mv "$root/app" "$root/app.old"; fi
mv "$root/app.new" "$root/app"
chown -R bitlogin:bitlogin "$root/app"

cat > "$conf/bit-login-oidc.env" <<'EOF'
HOST=127.0.0.1
PORT=16384
IDENTITY_ONLY=true
BASE_URL=https://81.70.17.186:9443
AUTH_DB_PATH=/var/lib/bit-login-oidc/auth.db
OIDC_ISSUER=https://81.70.17.186:9443
OIDC_CLIENT_ID=reimbursement-oa
OIDC_REDIRECT_URIS=https://81.70.17.186/api/auth/oidc/callback
OIDC_ACCESS_TOKEN_TTL=604800
OIDC_APP_TOKEN_TTLS=reimbursement-oa=604800
OIDC_SIGNING_KEY_FILE=/var/lib/bit-login-oidc/oidc-signing-key.pem
OIDC_UPSTREAM_CALLBACK_URL=https://sso.bit.edu.cn/gate/cas-success/personal-center-home-page?personId=667e67ca6b050d065ecbf781&pageId=666fffd2397df800012e5a4c&objectId=6889cb58bbce4700065c13b7
OIDC_UPSTREAM_CLIENT_ID=OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w
OIDC_ADMIN_STUDENT_IDS=3220251406
OIDC_ADMIN_SESSION_TTL=1800
OIDC_ADMIN_COOKIE_SECURE=true
HTTP_CONNECT_TIMEOUT=5
HTTP_READ_TIMEOUT=25
EOF
chown root:bitlogin "$conf/bit-login-oidc.env"
chmod 0640 "$conf/bit-login-oidc.env"

install -m 0644 /home/ubuntu/bit-login-build/BIT-Login/deploy/linux/bit-login-oidc.service /etc/systemd/system/bit-login-oidc.service
install -m 0644 /home/ubuntu/bit-login-build/BIT-Login/deploy/linux/bit-login-oidc.nginx.conf /etc/nginx/sites-available/bit-login-oidc
ln -sfn /etc/nginx/sites-available/bit-login-oidc /etc/nginx/sites-enabled/bit-login-oidc
nginx -t
systemctl daemon-reload
systemctl enable bit-login-oidc
systemctl restart bit-login-oidc
systemctl reload nginx
sleep 2
curl --fail --silent --show-error http://127.0.0.1:16384/ >/tmp/bit-login-oidc-health.json
cat /tmp/bit-login-oidc-health.json
