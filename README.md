# lore-auth-bridge

`lore-auth-bridge` は、[Lore](https://lore.org/) の認証・認可を提供する Rust サービスです。
Google、Microsoft Entra ID、Keycloak などの OIDC IdP と連携してユーザーを認証し、
ユーザー・グループ・repository ごとの権限を管理します。

bridge は Lore の UCS Auth / ReBAC protocol を実装し、ログイン用トークンの発行、
repository ごとのトークン交換、JWKS による検証鍵の配信、
`loreserver` との repository 作成・削除の同期を行います。管理には CLI または
任意で有効化する Web UI を使用できます。

主な実行ファイル:

- `lore-auth-server`: HTTP / gRPC サーバー
- `lore-authctl`: ユーザー、グループ、権限などを管理する CLI
- `lore-claimprobe`: Lore binary との JWT claim contract を検証する CLI

## ドキュメント

詳細は [radicalgrimoire の Lore ドキュメント](https://github.com/radicalgrimoire/radicalgrimoire/tree/main/lore) を参照してください。

- [bridge の構築手順](https://github.com/radicalgrimoire/radicalgrimoire/tree/main/lore/setup/lore-auth-bridge)
- [IdP を使わないローカル検証](https://github.com/radicalgrimoire/radicalgrimoire/blob/main/lore/setup/003-local-auth-quickstart.md)
- [bridge の開発・互換性検証](https://github.com/radicalgrimoire/radicalgrimoire/blob/main/lore/operations/006-bridge-validation.md)
- [token 発行と device flow](https://github.com/radicalgrimoire/radicalgrimoire/blob/main/lore/operations/005-token-flows.md)

JWT、IdP の client secret、秘密鍵をログや repository に残さないでください。
一部の CLI や Web の token flow はトークン本文を表示するため、取り扱いに注意してください。

## Ubuntu でのビルドと配置

以下は Lore サーバーがインストール済みで、Rust/Cargo とビルドの前提条件が
用意されている環境向けです。Lore 本体のビルド・配置やパッケージのインストールは行いません。

まず bridge をビルドします。

```bash
bash scripts/build-ubuntu.sh
```

`lore-auth-server` と `lore-authctl` が `target/release/` に作られます。
別のビルド先を使う場合は `--target-dir /path/to/target` を指定します。

次に、配置先を指定してビルド済みバイナリを配置します。

```bash
bash scripts/install-bridge-ubuntu.sh --bin-dir "$HOME/lore-auth/bin"
```

別のビルド先の場合は `--build-dir /path/to/target/release` も指定します。
同名の bridge 実行ファイルは置き換えます。オプションなしでは設定・DB・証明書や
Lore 本体には触れず、サービスも起動・再起動しません。

### bridge 設定と任意の初期化

[設定例](configs/lore-auth.example.yaml) を参考に `lore-auth.yaml` を自分で作り、
DB パス、JWT、IdP、TLS、Lore 接続先を環境に合わせて編集します。
`loreserver` 側の認証設定も bridge に合わせてください。
スクリプトは設定ファイルを生成・変更しません。

DB の作成・マイグレーションを実行する場合:

```bash
bash scripts/install-bridge-ubuntu.sh \
  --bin-dir "$HOME/lore-auth/bin" \
  --init-db --config "$HOME/lore-auth/lore-auth.yaml"
```

既存 DB を指定した場合もマイグレーションが適用されるため、事前にバックアップしてください。
初期化は bridge のサービスユーザーが DB を読み書きできる権限で実行します。
配置に管理者権限が必要な場合、DB を `root` 所有で作らないよう配置と初期化を別々に実行してください。
既存ファイルの権限は変更されません。

テストなどに自己署名 gRPC 証明書を生成する場合:

```bash
bash scripts/install-bridge-ubuntu.sh \
  --bin-dir "$HOME/lore-auth/bin" \
  --init-cert "$HOME/lore-auth/certs" --cert-host localhost
```

`grpc.crt` と `grpc.key` が生成されます。どちらかが存在する場合は上書きしません。
`--cert-host` には接続先の DNS 名または IPv4 を指定します。
設定の `server.grpc_tls_cert_file` / `server.grpc_tls_key_file` を生成先に合わせ、
クライアントでの証明書の信頼を別途設定してください。自己署名証明書は自動的に信頼されません。

`--init-db` と `--init-cert` は同時に使えます。途中で失敗しても、既に配置・初期化
されたものは自動で元には戻りません。JWT 署名鍵の生成とサービスの起動・再起動は別途行います。
各オプションは `bash scripts/install-bridge-ubuntu.sh --help` を参照してください。
