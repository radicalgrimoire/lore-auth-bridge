# Entra ID 連携の変更根拠と検証記録

この文書は、`lore-auth-bridge` を Microsoft Entra ID と連携させるために追加・修正した内容と、その必要性および検証結果を記録するものです。

構築手順は [172.20.12.193: Lore と lore-auth-bridge の構築記録](on-prem-entra-lore-server.ja.md) を参照してください。

## 対象 commit

bridge 側の実装は、fork の `main` に push 済みの次の commit です。

```text
602c5da Add Entra identity binding onboarding
```

変更は次の6 file です。

```text
crates/lore-auth-adapters/src/sqlite/accounts.rs
crates/lore-auth-adapters/src/sqlite/audited.rs
crates/lore-authctl/src/commands/user.rs
crates/lore-authctl/src/main.rs
doc/setup/authctl.ja.md
scripts/onboard-entra-user.sh
```

## なぜ変更が必要だったか

### Entra ID の email claim と既存 invitation flow の不一致

Microsoft Entra ID の ID token には email 相当の claim が含まれる場合があるが、この構成で取得した claim は `email_verified=false` だった。つまり bridge は email address の文字列を参照できても、その address が Entra ID により本人確認済みであるとは扱えない。

これは うちの会社 tenant の app registration を正しく設定していないためとは断定できない。Entra ID の `email` claim は、`email` scope や optional claim を設定して返却を要求できる場合がある一方、値が常に存在すること、正確であること、本人確認済みであることは保証されない。app registration の設定だけで `email_verified=true` を必ず得る前提にはできない。

Microsoft の ID token claim reference も、email、UPN、`preferred_username` のような人間可読で変更可能な値を authorization や永続的な user identification に使わず、安定した識別子として `oid`、必要に応じて `tid` と組み合わせて使うよう案内している。

参照: [Microsoft Entra ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)

これは bridge の不具合ではない。既存の `user invite` flow は、初回 login で email を account ownership の証明に使うため、次の条件を満たす identity だけを invitation に bind する設計である。

```text
identity.email が空でない
かつ identity.email_verified が true
かつ IdP/provider/issuer と invitation が一致する
かつ email domain policy を満たす
```

実装では `identity.email_verified` が false の時点で、invitation を検索する前に login resolution を `NotFound` として終了する。そのため、Entra login と callback は成功しても、`user invite` だけでは identity を bridge user に初回 bind できず、Lore token は発行されない。

この条件を緩めて未検証 email を invitation の本人確認に使うことはしなかった。email claim は変更可能であり、確認済みと保証されない address を account ownership の証明にすると、既存 invitation flow の security model を弱めるためである。

### Entra ID で本人を識別する値

Entra provider は、既存実装で subject strategy `entra_oid_tid` をサポートしている。この strategy は ID token の tenant ID (`tid`) と object ID (`oid`) を結合し、次の identity key を作る。

```text
<tenant-id>:<object-id>
```

`tid` は受け入れる tenant を表し、`oid` はその tenant 内の user を識別する。adapter は設定した `required_tid` と token の `tid` が一致しない場合、または `tid`/`oid` のいずれかがない場合に login を拒否する。

そこで、管理者が Entra 管理画面で確認した Object ID を使い、`<tenant-id>:<object-id>` を既存 bridge user に明示 bind する変更を追加した。次回 login では email の verified 状態ではなく、provider/issuer/subject の一致で既存 identity として解決される。

## 追加した実装

### `lore-authctl user bind-identity`

`lore-authctl` に次の管理 command を追加した。

```bash
lore-authctl --config lore-auth.yaml user bind-identity \
  --idp entra \
  --email alice@example.com \
  --subject "<tenant-id>:<object-id>"
```

command は `lore-auth.yaml` から provider ID、issuer、subject strategy を取得する。Entra 固有値を command 内で固定していないため、設定された IdP の identity key と login 時の identity key が一致する。

### SQLite identity binding

`external_identities` table に active identity を登録する処理を追加した。

- 対象 email の既存 bridge user を解決する。
- disabled user への bind を拒否する。
- provider ID、issuer、subject、subject strategy が空なら拒否する。
- 同じ provider/issuer/subject が同じ active user に bind 済みなら、既存 identity を返す。
- 同じ subject が別 user に bind 済み、または inactive identity なら拒否する。
- 新規 binding では user の email を記録し、status を `active` にする。

このため、同じ onboarding command は安全に再実行でき、別の bridge user が他者の Entra subject を取得することはできない。

### transaction と audit

binding は `TransactionBehavior::Immediate` transaction 内で実行する。

identity INSERT と `user.bind_identity` の admin audit log は同じ transaction に入るため、audit log の記録に失敗した場合は identity だけが登録されない。

audit detail には provider ID、issuer、subject を残す。Entra の access token や client secret は記録しない。

### onboarding script

`scripts/onboard-entra-user.sh` を追加した。この script は次を順に実行する。

1. email の bridge user がなければ `user add` する。
2. `<tenant-id>:<object-id>` を `user bind-identity` で bind する。
3. `--repo` が指定されていれば、指定 role の repository grant を追加する。

同じ user binding と同じ grant は再実行時に追加しない。`--repo` を省略した場合、login identity だけを作り、repository への権限は付与しない。

## Entra 設定との対応

server の Entra provider 設定は次の値を使う。

```yaml
subject:
  strategy: entra_oid_tid
  required_tid: "ec5c9760-1e1d-4de3-a9ff-c2fcf61d617f"
```

`required_tid` により、別 tenant の token から作られた subject は受け付けない。OIDC adapter は `tid` または `oid` claim がない token も拒否する。

従って、管理者が `user bind-identity` に渡す subject は、この tenant ID と Entra 管理画面で確認した対象 user の Object ID を結合した値である必要がある。

## Lore 側の連携変更

bridge の外部 gRPC endpoint は `https://172.20.12.193:8081` である。Lore CLI がこれへ TLS 接続できるよう、別 workspace の `lore-transport/src/auth/ucs_auth.rs` も修正した。

- `https://` endpoint で `ClientTlsConfig::with_native_roots()` を設定する。
- gRPC の HTTP/2 を明示する。
- TLS connection error の debug detail を保持する。

これは bridge の Entra identity binding と別の変更だが、TLS 接続できなければ login 後の repository 操作で authz token exchange ができないため、実運用の Entra 連携には必要だった。

`lore-capi/lore.h` は認証構築のために内容変更していない。worktree の modified 表示は line ending によるもので、C API ABI/宣言の変更はない。

## 実機で確認したこと

`172.20.12.193` の構成で、次を確認した。

- bridge の browser login endpoint を `https://172.20.12.193:8080/login` として公開した。
- bridge gRPC endpoint を `https://172.20.12.193:8081` として公開した。
- Nginx が内部 TLS listener へ `grpcs://127.0.0.1:18081` で転送することを確認した。
- `CA:FALSE`、serverAuth、IP SAN を持つ bridge certificate に更新し、rustls の end-entity certificate rejection を解消した。
- Lore CLI の HTTPS gRPC trust 修正を含む release build を server へ配置した。
- Entra user `ueno` で CLI login し、`gamestudio/sandbox` repository を作成した。
- writer grant を付与した user が repository 操作できることを確認した。
- Entra Object ID を指定して `kitakado` user を bind した。
- `user bind-identity` command と `onboard-entra-user.sh` を既存 binding に対して再実行し、成功することを確認した。
- `user.bind_identity` audit record が SQLite に作成されることを確認した。

これらにより、Entra login、bridge identity resolution、JWT 発行、Lore の TLS gRPC 接続、ReBAC による repository authorization までの経路が実機で成立している。

## 自動検証と残る制約

次の command は成功した。

```bash
cargo check -p lore-authctl
cargo test -p lore-auth-adapters --test sqlite
```

SQLite integration test は 24件成功した。ただし、今回追加した binding 専用の automated test はまだ追加していない。今後は少なくとも次を test 化する。

- unverified Entra email でも、事前 bind 済み subject なら login を解決できること。
- 同じ user/subject の bind が冪等であること。
- 別 user に同一 subject を bind すると拒否されること。
- disabled user への bind を拒否すること。
- audit INSERT が失敗した場合に identity INSERT も rollback されること。


