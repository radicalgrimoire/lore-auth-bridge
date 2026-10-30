# Microsoft Entra ID

Microsoft Entra ID を login に使う場合は、tenant に Web application を登録し、その Application client ID、client secret、redirect URL を bridge に設定します。

bridge は Entra ID login で得た identity を、bridge DB に登録されたユーザーと照合します。

Entra ID login に成功しただけでは、Lore の利用者にはなりません。

このページは Microsoft Entra ID の一般的な app registration 手順と bridge の設定を説明します。
実際の画面、条件付きアクセス、service user、ファイル配置は環境ごとに確認してください。

## 必要なもの

Microsoft Entra ID を有効にするには、次の値を用意します。

- **Tenant ID**：bridge が受け入れる Directory tenant ID。
- **Application client ID**：Entra app registration の application ID。
- **Client secret**：app registration で作成した secret value。
- **Redirect URL**：Entra ID login 後に Entra ID が戻す bridge の callback URL。
- **User email**：verified-email invitation を使う場合に bridge へ登録する email。

`client_secret_file` には secret の値ではなく、secret を保存したファイルパスを書きます。

issuer には `https://login.microsoftonline.com/{tenant}/v2.0` 形式の tenant 固定 URL を使います。

`subject.required_tid` には Directory tenant ID を設定します。

Entra ID の bridge subject は、ID token の `tid` claim と `oid` claim から作ります。

email、UPN、`preferred_username` は使いません。

## Microsoft Entra で取得する値

Microsoft Entra ID で app registration を作成するか、既存のものを選びます。

Microsoft Entra admin center の画面名や導線は変わることがあるため、以下は概念手順として扱ってください。

- Register an application in Microsoft Entra ID: https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app
- Microsoft identity platform OpenID Connect: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

## App registration

bridge 用の app registration を作成します。

多くの bridge deployment では、Lore user を持つ tenant に対する single-tenant app registration を使います。

Application client ID と Directory tenant ID を控えます。

application を Web application として設定し、bridge の callback URL を完全一致で登録します。

ローカルでは次の URI を登録します。

```text
http://localhost:8080/auth/entra/callback
```

本番では公開 URL に合わせます。

```text
https://auth.example.com/auth/entra/callback
```

app registration の「Certificates & secrets」で client secret を作成し、表示されている間に
**Value** を安全な credential store に保存します。**Secret ID ではありません**。Value は
作成時以外には再表示できないため、失った場合は新しい secret を発行します。有効期限と
更新担当者も記録してください。secret の値は記録しません。

Entra ID 側の redirect URI と、bridge config の `identity_providers.providers.entra.redirect_url` は同じ文字列にします。

scheme、host、port、path、末尾の slash が違うと callback は失敗します。

## bridge 設定

ローカルで Entra ID を試す場合は次のように設定します。

```yaml
server:
  public_base_url: "http://localhost:8080"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: ".quickstart/entra_client_secret"
      redirect_url: "http://localhost:8080/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

Client secret は YAML に直接書かず、`.quickstart/entra_client_secret` に保存します。
以下の[ファイル配置と検証](#client-secret-のファイル配置と検証)に従い、secret を
shell command に直接入力せず、安全な手段でファイルに渡してください。

本番では HTTPS の公開 URL を使います。

```yaml
server:
  public_base_url: "https://auth.example.com"

identity_providers:
  default: entra
  providers:
    entra:
      type: oidc
      profile: entra
      display_name: "Microsoft Entra ID"
      issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "<Application client ID>"
      client_secret_file: "/etc/lore-auth/entra_client_secret"
      redirect_url: "https://auth.example.com/auth/entra/callback"
      scopes: [openid, email, profile]
      pkce: required
      subject:
        strategy: entra_oid_tid
        required_tid: "<tenant-id>"
      trust:
        email_binding: verified_email_invitation
        allowed_email_domains:
          - "example.com"
```

## Client secret のファイル配置と検証

`client_secret_file` は secret の **Value だけ**を含む UTF-8 ファイルへのパスです。
bridge は起動時にファイルを読み込み、値の前後の空白や改行を取り除きます。空ファイルや
読み取れないファイルでは起動できません。相対パスは bridge process の作業ディレクトリを
基準に解決されるため、本番では絶対パスを使います。

1. 信頼できる管理端末と管理者だけが使える操作環境を用意します。secret の Value を
   shell の引数、環境変数、history、ログ、chat、source control に残さないでください。
   editor や転送ツールを使う場合は、一時ファイル・バックアップ・共有 clipboard にも注意します。
2. 限定されたディレクトリに Value を安全に配置します。ファイルは管理者が更新し、
   bridge の service user が読み取れるようにします。例えば root 所有・service group 読み取り可の
   `0640` を使い、親ディレクトリの通過権限も確認します。bridge に書き込み権限を与える必要は
   ありません。不要な user には読み取りを許可しません。既存ファイルを上書きする場合は、
   後述の更新手順を使います。
3. `client_secret_file` をそのファイルの絶対パスに設定します。設定ファイルには Value を書きません。
4. bridge と同じ service user で、内容を表示せず読み取り権限を確認します。次は
   `systemd/lore-auth.service` の service user `lore-auth` を使う例です。

   ```bash
   sudo -u lore-auth test -r /etc/lore-auth/entra_client_secret
   ```

5. サーバー上で次の検証スクリプトを実行します。source checkout の場所、tenant ID、
   application client ID、secret ファイルのパスは実環境に合わせます。スクリプトの実行者にも
   ファイルの読み取り権限と Python 3 が必要です。

   ```bash
   bash ./scripts/verify-entra-client-secret.sh \
     --tenant-id "<tenant-id>" \
     --client-id "<application-client-id>" \
     --secret-file "/etc/lore-auth/entra_client_secret"
   ```

この検証はサーバーから Entra の token endpoint に HTTPS で接続し、Microsoft Graph 向けの
`client_credentials` token を要求します。Secret や取得した token は表示しません。
検証するのは指定したファイルの内容です。ファイル変更後に bridge を再起動していない場合、
実行中の process が保持する Secret と異なることがあります。
`OK` はその要求が受理されたことを示しますが、ブラウザー login、条件付きアクセス、
redirect URI、ユーザー登録、Lore 権限まで保証するものではありません。失敗時も必ずしも
Secret の誤りとは限らず、tenant / client ID、アプリ設定、利用可能な権限、network、
DNS、TLS、proxy などを確認してください。`invalid_client` の場合は Value と Secret ID の
取り違えや期限切れも確認します。エラーを共有するときは機密情報を含めないでください。

## Client secret の更新

新しい Value は Entra 側で発行してから、サーバー管理者が更新します。bridge の管理 Web UI
では確認・変更しません。

1. 利用者に認証サービスの一時停止を周知し、復旧手順と作業権限を確認します。新旧 Secret の
   有効期間を重ね、旧 Secret をすぐに削除しないようにします。必要な復旧用コピーは
   アクセス制限された安全な保管先で管理します。
2. 新しい Value を別の制限された一時ファイルに安全に配置し、そのファイルを指定して上記の
   検証スクリプトを実行します。検証に失敗した場合は既存ファイルを変更しません。
3. 新しいファイルを `client_secret_file` の場所に配置します。部分的な書き込みを読ませないよう、
   同じファイルシステム上に準備してから原子的に置き換えます。所有者・権限と親ディレクトリの
   権限を確認し、service user で読み取り可能なことを確認します。
4. bridge を再起動します。bridge は起動時に Secret を読み込むため、ファイルの差し替えだけでは
   実行中の process に反映されません。下記は付属の systemd unit を使用する例です。実際の
   service 名を確認してから実行してください。

   ```bash
   sudo systemctl restart lore-auth.service
   sudo systemctl is-active lore-auth.service
   ```

5. service が active であることと、実際の Entra browser login および必要な Lore repository
   操作を確認します。health check や検証スクリプトの成功だけでは login 完了を確認できません。
   問題があれば旧 Secret が有効な間に旧ファイルを復元して bridge を再起動し、原因を調査します。
   切り替え成功後、組織の手順に従い不要な一時ファイルを安全に削除し、旧 Secret の失効を検討します。

## Entra ID の subject と trust

`subject.strategy: entra_oid_tid` では `subject.required_tid` が必須です。

tenant を固定することで、複数 tenant が関係する Entra setup での subject 衝突を防ぎます。

OIDC adapter は ID token の `tid` claim と `oid` claim を読み、bridge subject を `tid:oid` として保存します。

`trust.email_binding: verified_email_invitation` では、ID token に pending invitation と一致する verified email が含まれる必要があります。

正確な binding と `trust.allowed_email_domains` の規則は [Configuration](configuration.md#identity_providers) を参照してください。

## ユーザー登録

Entra ID login が成功しても、対応するユーザーが bridge DB に登録されていなければ token は発行されません。

通常は、管理者が対象ユーザーの email を登録します。

```bash
lore-authctl --config .quickstart/lore-auth.yaml user invite \
  --idp entra \
  --email '<Entra user email>' \
  --name '<display name>'
```

この時点では Entra account との連携がまだ完了していないため、token は発行されません。

招待されていない場合、token は発行されません。

招待を作成してから、もう一度 `/login` を開くと bridge のブラウザセッションが作成されます。

```text
http://localhost:8080/login
```

## 動作

bridge は callback で Entra ID token を検証します。

検証後、token の tenant ID を `subject.required_tid` と照合します。

次に provider ID、issuer、`tid:oid` subject を `external_identities` と照合します。

active な binding があれば、ブラウザセッションまたは CLI auth session が完了します。

active な binding がない場合は、[Configuration](configuration.md#identity_providers) の generic invitation-binding policy が適用されます。

binding または invitation と照合できない場合は token を発行せず、whoami 画面を表示します。

## よくある失敗

callback handling が失敗する場合は、Entra ID に登録した redirect URI と `identity_providers.providers.entra.redirect_url` が完全一致しているか確認します。

Entra ID login は成功しているのに Lore token が発行されない場合は、`lore-authctl --config <cfg> user invite --idp entra` で verified email を招待してから login をやり直します。

callback 後に login が拒否される場合は、ID token の `tid` claim が `subject.required_tid` と一致しているか確認します。

bridge が `entra_oid_tid` には `tid` と `oid` claim が必要だと報告する場合は、app registration と issuer が想定 tenant の Entra ID token を返しているか確認します。

invitation が消費されない場合は、ID token に想定 email が含まれ、その email が provider claim 上で verified として扱われているか確認します。

`identity_providers.providers.entra.client_id`、`identity_providers.providers.entra.client_secret_file`、`identity_providers.providers.entra.redirect_url` のどれかが空の場合、Entra ID login は有効になりません。
