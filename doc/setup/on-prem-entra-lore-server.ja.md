# 172.20.12.193: Lore と lore-auth-bridge の構築記録

これは `172.20.12.193` に Lore と `lore-auth-bridge` を構築し、Microsoft Entra ID 認証を有効化したときに実行した作業の記録です。

Entra client secret と Nginx の公開 certificate/private key の実体は記載しません。

## Ubuntu の build prerequisite を入れる

```bash
# Rust/Cargo が native dependency を build するための compiler、OpenSSL header、CMake を入れる。
sudo apt-get update
sudo apt-get install -y build-essential ca-certificates cmake curl git \
  libssl-dev openssl pkg-config rsync nginx

# Rust toolchain がない場合に rustup で入れる。
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## Windows workspace の source tree を server へ転送する

```bash
# Windows/WSL 側で実行する。target は server 上で release build するため転送しない。
rsync -a --delete --exclude .git --exclude target \
  <local-path>/lore-auth-bridge/ mgs@172.20.12.193:~/src/lore-auth-bridge/
rsync -a --delete --exclude .git --exclude target \
  <local-path>/lore/ mgs@172.20.12.193:~/src/lore/
```

WSL の `/mnt/<drive>` で Cargo build すると build script が失敗する場合があるため、server 上の Linux filesystem で build する。

## bridge と Lore を release build する

```bash
# bridge server と運用 CLI を build する。
source "$HOME/.cargo/env"
cd ~/src/lore-auth-bridge
cargo build --release -p lore-auth-server -p lore-authctl

# Lore CLI と Lore server を build する。
cd ~/src/lore
cargo build --release -p lore-client --bin lore -p lore-server --bin loreserver
```

## build 済み binary を運用 directory へ置く

```bash
# bridge binary を /home/mgs/lore-auth 配下へ置く。
install -d -m 0750 /home/mgs/lore-auth/bin
install -m 0755 ~/src/lore-auth-bridge/target/release/lore-auth-server \
  /home/mgs/lore-auth/bin/lore-auth-server
install -m 0755 ~/src/lore-auth-bridge/target/release/lore-authctl \
  /home/mgs/lore-auth/bin/lore-authctl

# Lore binary を /datadrive2/lore 配下へ置く。
install -d -m 0750 /datadrive2/lore/bin
install -m 0755 ~/src/lore/target/release/lore /datadrive2/lore/bin/lore
install -m 0755 ~/src/lore/target/release/loreserver /datadrive2/lore/bin/loreserver
```

## bridge の data directory を作る

```bash
# SQLite、JWT signing key、gRPC certificate、Entra secret の配置先を作る。
install -d -m 0700 /home/mgs/lore-auth/data
install -d -m 0700 /home/mgs/lore-auth/keys
install -d -m 0700 /home/mgs/lore-auth/certs
install -d -m 0700 /home/mgs/lore-auth/config

# Entra client secret を bridge だけが読める file として配置する。
install -m 0600 <entra-client-secret-file> \
  /home/mgs/lore-auth/config/entra-client-secret
```

## bridge gRPC certificate を作る

bridge は `127.0.0.1:18081` で gRPC TLS listener を持つ。Nginx がこの listener へ `grpcs://` で proxy するため、bridge 用 certificate と private key を作成した。

```bash
# gRPC の server certificate と private key を作る。
# CA:FALSE にする。CA:TRUE の certificate は rustls が server certificate として拒否する。
CERT_DIR=/home/mgs/lore-auth/certs
HOST=172.20.12.193

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=$HOST" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:172.20.12.193" \
  -keyout "$CERT_DIR/grpc.key" \
  -out "$CERT_DIR/grpc.crt"
chmod 0600 "$CERT_DIR/grpc.key"
chmod 0644 "$CERT_DIR/grpc.crt"

# SAN と CA:FALSE が入っていることを確認する。
openssl x509 -in "$CERT_DIR/grpc.crt" -noout -text \
  | grep -A1 -E 'Basic Constraints|Subject Alternative Name'
```

`grpc.crt` は自己署名 certificate のため、Lore CLI を使う Windows PC の Trusted Root Certification Authorities に import した。

## bridge 設定を書く

```bash
# listener、SQLite、JWT、Entra、Lore 接続先を設定する。
cat > /home/mgs/lore-auth/lore-auth.yaml <<'YAML'
server:
  listen: "127.0.0.1:18080"
  grpc_listen: "127.0.0.1:18081"
  grpc_tls_cert_file: "/home/mgs/lore-auth/certs/grpc.crt"
  grpc_tls_key_file: "/home/mgs/lore-auth/certs/grpc.key"
  public_base_url: "https://172.20.12.193:8080"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/ec5c9760-1e1d-4de3-a9ff-c2fcf61d617f/v2.0"
      client_id: "<client-id>"
      client_secret_file: "/home/mgs/lore-auth/config/entra-client-secret"
      redirect_url: "https://172.20.12.193:8080/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "ec5c9760-1e1d-4de3-a9ff-c2fcf61d617f"
      trust:
        email_binding: verified_email_invitation

database:
  path: "/home/mgs/lore-auth/data/lore-auth.sqlite3"

authz:
  backend: rebac

jwt:
  issuer: "https://172.20.12.193:8080"
  audience: ["lore-service", "172.20.12.193"]
  ttl_seconds: 3600
  signing_key_dir: "/home/mgs/lore-auth/keys"
  active_kid: "lore-entra-01"

lore:
  default_remote_url: "lore://172.20.12.193:41337"
  auth_url: "https://172.20.12.193:8081"

security:
  rebac_allowed_peer_cidrs: ["127.0.0.1/32"]
YAML
chmod 0600 /home/mgs/lore-auth/lore-auth.yaml
```

Entra application の redirect URI には、上記と完全に同じ `https://172.20.12.193:8080/auth/entra/callback` を登録した。

## bridge SQLite database と JWT signing key を作る

SQLite server を別途 install する必要はない。`init-db` が `/home/mgs/lore-auth/data/lore-auth.sqlite3` を作成して schema を初期化する。

```bash
AUTHCTL=/home/mgs/lore-auth/bin/lore-authctl
CONFIG=/home/mgs/lore-auth/lore-auth.yaml

# bridge の SQLite database を作成して schema を初期化する。
$AUTHCTL --config "$CONFIG" init-db

# bridge が Lore 用 JWT に署名する RS256 key を作成する。
$AUTHCTL --config "$CONFIG" signing-key generate --kid lore-entra-01
```

## Nginx で bridge を 8080/8081 に公開する

bridge は外部へ直接公開せず、Nginx 経由で公開した。HTTP は `:8080`、gRPC は `:8081` とした。bridge の gRPC upstream は TLS なので、`grpc_pass grpcs://127.0.0.1:18081` を使用する。

```nginx
# /etc/nginx/sites-available/lore-auth
server {
    listen 8080 ssl;
    server_name 172.20.12.193;
    ssl_certificate     <nginx-public-certificate>;
    ssl_certificate_key <nginx-public-private-key>;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 8081 ssl http2;
    server_name 172.20.12.193;
    ssl_certificate     <nginx-public-certificate>;
    ssl_certificate_key <nginx-public-private-key>;

    location /ucs.auth.RebacApi/ {
        # ReBAC は loreserver の resource sync 専用にする。
        allow 127.0.0.1;
        deny all;
        grpc_pass grpcs://127.0.0.1:18081;
        grpc_ssl_verify off;
    }

    location / {
        grpc_pass grpcs://127.0.0.1:18081;
        grpc_ssl_verify off;
    }
}
```

```bash
# Nginx 設定を有効化して反映する。
sudo ln -s /etc/nginx/sites-available/lore-auth /etc/nginx/sites-enabled/lore-auth
sudo nginx -t
sudo systemctl reload nginx
```

`grpc_ssl_verify off` は、Nginx から loopback の自己署名 bridge certificate へ接続するために設定した。外部 client から Nginx への TLS 検証を無効にするものではない。

## Lore server の auth 設定を書く

```bash
# Lore server が bridge の JWT を検証し、ReBAC を問い合わせるための設定を書く。
install -d -m 0750 /datadrive2/lore/config /datadrive2/lore/data/store

cat > /datadrive2/lore/config/dev.toml <<'TOML'
[environment.endpoint]
auth_url = "https://172.20.12.193:8081"

[server.auth]
jwt_issuer = "https://172.20.12.193:8080"
jwt_audience = ["lore-service", "172.20.12.193"]

[server.auth.jwk]
endpoint = "https://172.20.12.193:8080/.well-known/jwks.json"

[immutable_store.local]
path = "/datadrive2/lore/data/store"

[mutable_store.local]
path = "/datadrive2/lore/data/store"
TOML
```

## Lore の HTTPS gRPC client を修正して build し直す

`lore-transport/src/auth/ucs_auth.rs` を修正した。`https://` の auth endpoint へ接続するときに native trust root と HTTP/2 を明示し、TLS 接続 error を確認できるようにした。

```rust
ClientTlsConfig::new()
    .assume_http2(true)
    .with_native_roots()
```

この変更後に、前述の Lore release build を実行し、更新された `lore` と `loreserver` を `/datadrive2/lore/bin` へ install した。

`lore-capi/lore.h` は認証構築のために内容変更していない。modified 表示は line ending によるもので、C API の ABI/宣言に変更はない。

## bridge と Lore server を起動する

```bash
# bridge を起動する。Nginx は 18080/18081 の loopback listener へ転送する。
/home/mgs/lore-auth/bin/lore-auth-server \
  --config /home/mgs/lore-auth/lore-auth.yaml

# 別 terminal または service manager で Lore server を起動する。
LORE_CONFIG_PATH=/datadrive2/lore/config \
LORE_ENV=dev \
/datadrive2/lore/bin/loreserver \
  --config /datadrive2/lore/config --env dev
```

実運用では `loreserver` を systemd service として起動した。設定変更後は `sudo systemctl daemon-reload` と `sudo systemctl restart lore` を実行する。

## 起動後に endpoint を確認する

```bash
# bridge HTTP/JWKS と gRPC TLS endpoint を確認する。
curl -fk https://172.20.12.193:8080/healthz
curl -fk https://172.20.12.193:8080/.well-known/jwks.json
openssl s_client -connect 172.20.12.193:8081 -servername 172.20.12.193 </dev/null
```

## Entra user を登録して repository 権限を与える

Entra の `email_verified` は false になることがあるため、email invitation だけに依存せず Entra Object ID を bridge user に bind する。

```bash
# user を作成し、Entra Object ID を bind し、repository grant を追加する。
/home/mgs/lore-auth/bin/onboard-entra-user.sh \
  --email alice@example.com \
  --name "Alice Example" \
  --object-id "<entra-object-id>" \
  --repo gamestudio/sandbox \
  --role writer
```

最後に Windows PC へ `grpc.crt` を配布して trusted root に import し、`lore auth login lore://172.20.12.193:41337` を実行した。login 後は repository create または clone/push を実行し、認証だけでなく ReBAC による repository 権限も確認した。
