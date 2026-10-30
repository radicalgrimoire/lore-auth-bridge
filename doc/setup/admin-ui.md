# 管理 Web UI

管理 Web UI は、login、JWKS、device flow、health check と同じ HTTP process で提供されます。

管理 Web UI の表示言語は英語のみです。

`admin.admin_emails` に 1 件以上の address がある場合だけ、`/admin` に mount されます。

`admin.admin_emails` を省略した場合、または空の場合、`/admin` は mount されず 404 を返します。

## UI の有効化

`lore-auth.yaml` に admin section を追加します。

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

列挙した address は正規化してから比較されます。

operator は `/admin` を直接開くと、未ログインの場合は OIDC ログインへ移動し、ログイン後に `/admin` に戻ります。ログイン後も有効なユーザーのメールアドレスが `admin.admin_emails` と一致する必要があります。

未ログインの `/admin` への GET はログインへリダイレクトされるため、admin UI が有効なことは外部から判別できます。非 admin、許可されていない peer、および未認証のその他の admin request は 404 を返します。

## ネットワーク制限

`/admin` は公開 HTTP listener と同居します。

本番では、bridge を NGINX や Caddy などの reverse proxy の背後に置き、edge 側で `/admin` を制限してください。

公開境界で送信元制限や強い rate limit が必要な場合は、Cloudflare などの CDN または WAF も使います。

bridge は第二層の peer filter も持ちます。

```yaml
security:
  admin_allowed_peer_cidrs:
    - "127.0.0.1/32"
```

この判定は、bridge が直接見る TCP peer address を使います。

reverse proxy の背後では、proxy の address を許可し、公開側の admin allowlist は proxy で強制してください。

この判定では `X-Forwarded-For` を信頼しません。

reverse proxy なしの最小構成では、admin の防御は OIDC login、`admin.admin_emails`、任意の `security.admin_allowed_peer_cidrs` だけです。

## 機能

UI では repository、user、group、grant、user access を閲覧および検索できます。

user の追加と無効化、repository の作成と認可レコードの無効化、grant 管理、group 管理ができます。

repository 作成を有効にするには `lore.repository_create_url` に Lore サーバーの gRPC エンドポイントを設定します。同一ホスト上なら `http://127.0.0.1:41337` を使用できます。HTTP はループバック IP のみ使用可能で、それ以外はホストが信頼する証明書を持つ HTTPS が必要です。未設定では作成できません。Lore サーバーは `lore.repository.v1.RepositoryService` に対応し、ReBAC を通じてこの bridge にリソースを同期する必要があります。

Repositories のフォームは Lore に repository と `main` ブランチを作成します。Name は必須、Organization は任意で、指定時は `Organization/Name` になります。各部分に使えるのは半角英数字、`-`、`_`、`.` で、先頭の `.` は使えません。作成はサインイン中の管理者の認証で実行され、bridge は同期された認可レコードを確認した後に管理監査を記録します。Lore の作成、同期、監査を一つのトランザクションにはできないため、結果が不明または一部成功と表示された場合は、再試行前に表示された repository ID を使って Lore と認可レコードを確認してください。

Server settings ではメンテナンスモードと削除前の待機時間（分、既定15分）を設定できます。メンテナンス状態は再起動後も保持され、サーバーと authctl からの新規トークン発行を停止しますが、発行済みトークンは失効しません。待機時間はまだ強制されません。期限を個別指定したトークンや Lore の期限判定の猶予は管理者が確認する必要があります。

Repository の View access ではユーザーとグループへの直接グラントを一覧・検索し、追加・解除できます。グループ経由やサーバー管理者権限によるアクセスは直接グラントとして表示されません。無効化にはメンテナンスモードが必要で、グラントは保持されます。無効化後は確認チェックを入れて対象 repository の直接グラントを一括削除できます。再有効化しても削除したグラントは復元されません。Lore の削除と復旧の実装が完了するまで、この画面からの repository 削除は利用できず、Lore 本体・認可登録のどちらも削除されません。実装済みの各管理操作と監査記録は同一トランザクションで処理されます。CLI と ReBAC による削除は従来どおりです。

`subject.strategy: entra_oid_tid` の Entra ID provider が設定されている場合、Users 画面に「Entra ID ユーザー追加」フォームが表示されます。メール、表示名、Entra ID のオブジェクト ID を入力すると、`lore-authctl user add` と `user bind-identity --idp entra` を 1 トランザクションで実行したのと同じ結果になり、追加後すぐにサインインできます。subject は `<required_tid>:<オブジェクト ID>` として保存されます。表示名を省略するとメールを使います。

user の直接追加は、ログイン binding を持たない account を作る advanced 操作です。

Server settings では Client ID、表示名（省略時は Client ID）、既存グループを指定してサービスアカウントを作成できます。作成・グループ所属・監査記録は一括確定されます。生成された Client Secret は作成結果に一度だけ表示されるので、安全な credential store に保存してください。紛失時は `lore-authctl service-account rotate` で再発行します。このフォームでは repository grant やネットワーク CIDR を設定しません。許可 CIDR はグループの View access または `lore-authctl` で設定できます。接続元 IP が適用される許可 CIDR に一致しない場合、サービスアカウントの認証は拒否されます。

Users の「アクセスを見る」画面では表示名を変更でき、紐づいている Entra ID のテナント ID とオブジェクト ID を確認できます。ID は保存済みの紐づけから表示され、Entra ID に問い合わせて確認するものではありません。

Groups 画面はグループ名と内部 ID を一覧表示します。View access では直接所属するメンバーを名前・メール・ユーザー ID で検索でき、メールまたはユーザー ID による追加と所属解除ができます。グループとメンバーの一覧は途中で打ち切りません。グループ一覧の Actions 列は将来の操作用です。

View access ではグループの許可接続元 IP の一覧・追加・解除もできます。IPv4・IPv6 アドレスまたは CIDR を入力でき、単一アドレスは `/32` または `/128` として登録されます。ネットワークは正規化されます。ユーザーに適用される全グループの CIDR は合算され、適用される CIDR が一つもない通常ユーザーのログインには IP 制限がありません。一方、サービスアカウントの認証には一致する CIDR が必要です。変更しても発行済みトークンは無効化されません。

同画面で紐づけのテナント ID とオブジェクト ID を修正できます。テナント ID は該当 provider の設定済み `required_tid` と一致する必要があります。変更は次回以降のサインインに適用され、既存のセッションや発行済みトークンは無効化されません。

同画面の「Manage direct repository access」では、有効なリポジトリをすべて名前・Resource ID・ユーザーへの直接ロール選択とともに表示します。各リポジトリで None、Reader、Writer、Admin を選び、最後に一括保存します。グループやサーバー管理者の権限を含む実効権限は別に表示し、このフォームでは変更しません。既に直接ロールが複数ある場合は「Keep existing roles」で保持され、別の選択肢を選んだ場合のみ変更されます。変更と監査記録は一括して確定され、表示時から直接 grant が変更されていた場合は保存に失敗します。発行済みトークンは無効化されません。フォームのリクエスト上限は 8 MiB です。

Groups 画面と `lore-authctl` のどちらからも nested group を新規作成することはできません。一度だけ実行される `phase7_remove_existing_group_nests_20261030` migration は既存の group 間の所属をすべて解除し、それぞれを admin audit に記録します。server または `lore-authctl` が DB を開く際に実行されます。更新前に DB をバックアップし、継承していた repository 権限と service account の許可 CIDR を確認してください。発行済み token は取り消されません。残存する nested group は管理画面で表示でき、管理画面または CLI で解除できます。

check simulator は Server settings の `/admin/server-settings/simulator` から利用できます。user、repository、action を入力して設定済み authorization policy を実行します。

simulator は nested group path を含む grant 根拠も補助情報として表示します。

`admin.global_repository_admin` が有効で該当する場合、暗黙の権限をサーバー管理者の根拠として表示します。これは保存された grant ではありません。[Configuration](configuration.md#admin) を参照してください。

policy の結果が正です。

admin mutation は `admin_audit` に記録されます。

SQLite を直接確認する例です。

```bash
sqlite3 /var/lib/lore-auth/auth.sqlite3 \
  "SELECT created_at, actor, action, object_type, object_id, detail FROM admin_audit ORDER BY created_at DESC LIMIT 20;"
```

## 復旧

admin の再有効化と IdP 障害時の手順は [Operations](operations.md#recovery) を参照してください。
