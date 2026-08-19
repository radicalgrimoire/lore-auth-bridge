# Entra ID 対応: lore-auth-bridge 更新履歴と根拠

この文書は、Git history と `origin/main..main` の差分を基に、今回の fork で `lore-auth-bridge` をなぜ更新したかを説明するものです。

構築 command は [172.20.12.193: Lore と lore-auth-bridge の構築記録](on-prem-entra-lore-server.ja.md)、実機検証の詳細は [Entra ID 連携の変更根拠と検証記録](entra-id-integration-evidence.ja.md) に分けています。

## 差分の範囲

2026-08-20 時点で、元 repository の `origin/main` に対する fork の `main` の code 差分は次の1 commit です。

```text
602c5da Add Entra identity binding onboarding
```

この commit は6 file、254行の追加と1行の変更である。

```text
M crates/lore-auth-adapters/src/sqlite/accounts.rs
M crates/lore-auth-adapters/src/sqlite/audited.rs
M crates/lore-authctl/src/commands/user.rs
M crates/lore-authctl/src/main.rs
M doc/setup/authctl.ja.md
A scripts/onboard-entra-user.sh
```

したがって、以下は元 repository 全体の機能一覧ではなく、この fork が追加した更新の説明である。

## 更新前に存在していた基盤

元 repository の過去 commit には、今回の更新で利用した次の基盤がすでに存在していた。

| Commit | 日付 | 既存機能 | 今回との関係 |
| --- | --- | --- | --- |
| `5505a86` | 2026-07-02 | OIDC adapter と IdP registry | Entra ID token を identity に変換する基盤 |
| `8a31d85` | 2026-07-02 | `lore-authctl` | DB、user、grant を運用する CLI |
| `619eb32` | 2026-07-02 | transactionally audited admin write | 管理変更を audit と同時に保存する基盤 |
| `99bc2db` / `40ddd50` / `8c7cfbf` | 2026-07-02 | ReBAC authorization | user/group と repository role を評価する基盤 |
| `12af80b` | 2026-07-03 | verified-email invitation を主 onboarding に設定 | Entra の未検証 email と衝突した既存運用経路 |
| `127d736` | 2026-08-18 | Entra ID setup guide | `entra_oid_tid` を設定する手順 |

特に OIDC adapter は `entra_oid_tid` strategy を持っている。この strategy は ID token の `tid` と `oid` から `<tenant-id>:<object-id>` を作り、`required_tid` と異なる tenant の token を拒否する。

## 発生した問題

Entra ID の実機 login では email claim が `email_verified=false` だった。

既存の `user invite` は「確認済み email が invitation の email と一致する」ことを初回 binding の条件にしている。そのため、次の flow は成立しなかった。

```text
user invite -> Entra browser login -> verified email による identity binding -> Lore token 発行
```

login callback 自体は完了しても、bridge は未登録 user として扱い、Lore CLI の login session は token 発行まで進まない。

この問題を email の強制信頼で回避してはならない。未検証 email をそのまま account ownership の証明にすると、IdP claim の意味を弱めるためである。

## 更新方針

既存の `entra_oid_tid` が作る tenant ID + Object ID を、管理者が Entra 管理画面で確認してから bridge user に明示的に bind する方針にした。

```text
Entra 管理画面の Object ID
  -> <tenant-id>:<object-id>
  -> bridge external_identities row
  -> 次回 Entra login の provider/issuer/subject と一致
  -> Lore token を発行
```

この方法なら、email verified claim に依存せず、Entra tenant 内で安定する Object ID を identity key に使える。

## 602c5da の変更内容と根拠

### CLI: `user bind-identity`

`crates/lore-authctl/src/main.rs` と `crates/lore-authctl/src/commands/user.rs` に次を追加した。

```bash
lore-authctl --config lore-auth.yaml user bind-identity \
  --idp entra \
  --email alice@example.com \
  --subject "<tenant-id>:<object-id>"
```

この command は YAML config から provider ID、issuer、subject strategy を読む。subject strategy を command に固定しないため、login 時に OIDC adapter が生成する identity key と運用者が登録する identity key を同じ設定で揃えられる。

### SQLite: identity の安全な登録

`crates/lore-auth-adapters/src/sqlite/accounts.rs` に `bind_external_identity_conn` を追加した。

この処理は次を保証する。

- bind 先は既存かつ active な bridge user である。
- provider ID、issuer、subject、subject strategy は空でない。
- 同一 provider/issuer/subject が同じ active user にある場合は成功として既存 row を返す。
- 同一 subject が別 user にある場合、または既存 identity が inactive の場合は拒否する。
- 新規 identity は `external_identities` table に active row として保存する。

これは、onboarding script を安全に再実行できることと、別 user が他者の Entra subject を取得できないことのために必要である。

### Audit: DB 更新と記録を同時に確定

`crates/lore-auth-adapters/src/sqlite/audited.rs` に `bind_external_identity` を追加した。

identity binding と `user.bind_identity` audit record を `TransactionBehavior::Immediate` transaction で実行する。audit の INSERT に失敗した場合、identity binding も commit されない。

これは Entra user と bridge user の結び付けが権限に直結する管理操作であるためである。誰がいつどの provider/issuer/subject を bind したかを追跡できる必要がある。

### Script: team onboarding を一つの操作にする

`scripts/onboard-entra-user.sh` を追加した。

```bash
scripts/onboard-entra-user.sh \
  --email alice@example.com \
  --name "Alice Example" \
  --object-id "<object-id>" \
  --repo gamestudio/sandbox \
  --role writer
```

この script は user 作成、Entra identity binding、任意の repository grant を順に実行する。個別に SQLite を編集する運用をなくし、入力値、冪等処理、grant 付与を同じ command にまとめるために追加した。

## この更新で可能になったこと

- Entra の `email_verified=false` を返す account を登録できる。
- Entra Object ID を管理者確認済み identity として bridge user に結び付けられる。
- 既存の ReBAC role (`reader`、`writer`、`admin`) を repository ごとに付与できる。
- 同じ user の再 onboarding を安全に実行できる。
- subject conflict は拒否され、管理操作は audit log に残る。

## 実機での根拠

`172.20.12.193` で次を確認済みである。

- `lore-authctl user bind-identity` が remote release binary の command list に現れる。
- `kitakado` user に Entra Object ID を bind できる。
- 同じ binding を再実行しても成功する。
- `onboard-entra-user.sh` が user、binding、grant を実行できる。
- `user.bind_identity` audit record が保存される。
- `ueno` user が Entra browser login 後に Lore CLI を認証し、`gamestudio/sandbox` repository を作成できる。
- writer grant を持つ user が repository 操作できる。

SQLite integration test は次で 24件成功した。

```bash
cargo test -p lore-auth-adapters --test sqlite
```

なお、`bind-identity` 専用の automated test はまだ追加していない。実機での動作確認は済んでいるが、subject conflict、disabled user、audit failure rollback を固定する test は今後の更新で追加すべきである。