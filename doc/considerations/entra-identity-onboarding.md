# Entra ID の本人識別とアカウント登録方式の考察

検討・実機確認日: 2026-11-04

## 要旨

- Entra ID の `tid`（テナント ID）と `oid`（ユーザーの Object ID）を、認証済みユーザーの識別キーとして保存する設計は妥当である。
- ただし Object ID 自体は認証の証拠ではない。検証済み ID token 内の値を、事前登録した identity と照合する。
- 現在の構成で実機ログインを確認したところ、bridge が参照する `email_verified` claim は欠落していた。明示的な `false` が返ったわけではない。
- この結果だけで Entra ID の構築・設定ミスとは判断できない。
- Object ID を永続識別に使うことと、管理者が Object ID を手入力することは別の設計判断である。
- Microsoft Graph から対象ユーザーの Object ID を取得し、管理者確認のうえで登録する仕組みは実現可能。ただし現時点では未実装である。

## 1. 確認を始めた理由

現在の bridge は、Entra ID ユーザーの登録時に Object ID を指定し、bridge 内のアカウントへ identity を紐づける。

この方式を採用した経緯は、当時の Entra login で email を確認済みとして扱えず、既存の email invitation による初回連携が成立しなかったことである。

今回の問いは、過去の理由の再説明ではなく、「現在の実装と Entra 設定なら、その前提を再検証して覆せるのではないか」だった。

過去の経緯は [Entra ID 連携の変更根拠と検証記録](../setup/entra-id-integration-evidence.md) と [更新履歴](../setup/entra-id-bridge-update-history.md) を参照する。

## 2. 現在の実装で分けるべき二つの処理

### Entra ID による認証

bridge は OIDC の ID token を受け取り、署名、issuer、audience、nonce などを検証する。`entra_oid_tid` strategy では、設定されたテナントと token の `tid` の一致、および `tid` / `oid` の存在も確認する。

これにより、Entra ID が認証したアカウントの identity を取得する。

### bridge アカウントへの紐づけ

検証した identity の provider、issuer、`tid:oid` に一致する登録があれば、既存の bridge ユーザーとして解決する。

未登録 identity の場合は、email invitation の条件を確認する。この経路は、email が存在し、`email_verified` が `true` であり、provider、issuer、招待、email domain policy などが一致する必要がある。

つまり、「Entra のログインに成功した」ことと、「その email を根拠に既存の bridge アカウントへ初回連携できる」ことは別である。

### ここでいう identity と「登録済み」の意味

identity は「外部の認証元で認証された、どのアカウントか」を表す情報である。この構成では provider、issuer、subject（`tid:oid`）の組み合わせで識別する。

bridge 内のアカウントと identity は同じものではない。

| 情報 | 役割 |
| --- | --- |
| bridge ユーザー | Lore 側で扱うユーザー。グループ所属や repository 権限の付与先になる |
| Entra identity | Entra が認証したアカウントを識別する情報 |
| binding（紐づけ） | 「この Entra identity は、この bridge ユーザーに対応する」という保存済みの対応関係 |

「identity が登録済み」とは、この binding が DB の `external_identities` に存在することを指す。bridge にメールと表示名だけのユーザーを作っても、Entra identity の登録が済んだことにはならない。

### なぜ「認証成功」だけで初回連携してはいけないのか

例えば、管理者が bridge に `alice@example.com` というユーザーを用意し、そのユーザーに repository 権限を付与していたとする。ここへ Entra で認証された identity が来たとき、必要なのは次の二つの判断である。

1. このログインは、Entra のどのアカウントによるものか。
2. そのアカウントに、bridge の Alice のユーザー・権限を引き継がせてよいか。

検証済み token の `tid:oid` は一つ目の判断に使える。しかし binding がなければ、二つ目の対応関係はまだ決まっていない。

ここで token 内の email が `alice@example.com` だったとしても、「Entra がその文字列を返した」ことと「そのアドレスの所有を確認した」ことは同じではない。token の署名検証は発行元と内容の改ざん有無を確認するものであり、各 claim に仕様以上の保証を追加するものではない。

メールの一致だけで自動連携すると、メール属性の誤設定、変更・再割り当てなどによって、意図しない identity に既存ユーザーの権限を渡す可能性がある。これは今回そうした事象を実測したという意味ではなく、初回連携の判断根拠を明確にする必要があるという話である。

テナントを限定することも必要だが、それだけでは「この identity が既存の Alice と同一人物である」という対応関係までは証明しない。

### 従来の email invitation が置いていた前提

従来方式は、管理者が「このメールの人を、この bridge ユーザーとして受け入れる」という招待を先に作る。その後、許可された認証元が同じメールについて `email_verified=true` を返した場合に、他の条件も確認して初回 binding を作る。

```text
管理者がメールで招待
  -> IdP で本人認証
  -> 確認済みメールと招待を照合
  -> 外部 identity と bridge ユーザーの binding を保存
  -> 次回以降は保存した identity で照合
```

この方式でも、メールは初回連携の手掛かりであり、その後の永続的な識別キーは外部 identity である。また、現在の実装が `email_verified=true` を要求していることと、その値だけで将来にわたり同一人物を保証できることは別である。

Entra 連携では、この「確認済みメール」という前提を得られなかった。そのため、email の条件を緩めるのではなく、管理者が対象アカウントの Object ID を確認して binding を先に作る方式を追加した。

### 登録済みなら `email_verified` がなくてもよい理由

保存済みの active binding があれば、今回の検証済み token の identity と対応関係を直接照合できる。初回連携のためにメール所有を推定する必要がないため、現在の実装はこの経路では `email_verified` を要求しない。

ただし、無条件でログインできるわけではない。token の検証、テナントの確認、有効な binding、有効な bridge ユーザーなどが必要であり、repository の操作には別途認可が必要である。

### 今回の経緯から導く結論

今回の再検証でも、観測したログインでは `email_verified` claim が欠落していた。従って、現行の email invitation の条件では、その identity をメールだけで初回連携することはできない。一方、保存済み binding を使うログインには、この欠落は障害にならない。

ここから導ける結論は「Object ID を人手で入力し続けるしかない」ではなく、**初回の対応関係を確定する、メール一致以外の信頼できる手続きが必要**ということである。

| 初回連携の方法 | 対応関係の判断根拠 | 現在の状況 |
| --- | --- | --- |
| 確認済みメールによる招待 | 管理者の招待と、IdP が確認済みとするメールの一致 | 実装済みだが、今回の Entra login は必要な claim を満たさない |
| Object ID の手動登録 | 管理者が確認した Entra アカウントと bridge ユーザーの対応 | 現在利用している方式 |
| Graph による検索・選択 | 対象テナントのディレクトリ情報を管理者が確認して対応づける | 実現可能だが未実装。第6節で検討 |

Graph 案は、Object ID による識別をやめるものではない。正しい Object ID を探して転記する作業を支援し、管理者の確認を経て同じ binding を作る案である。

実装:

- [OIDC token の検証と claim の読み取り](../../crates/lore-auth-adapters/src/oidc.rs)
- [SQLite の identity 照合と invitation binding](../../crates/lore-auth-adapters/src/sqlite/accounts.rs)

## 3. 193 サーバーでの再検証

### 未連携アカウントを用意しない方法を選んだ

初案は未連携アカウントでログインし、未登録時の Identity 画面に出る `email_verified` を見る方法だった。

しかし、新しい Entra アカウントを容易には用意できない。また、既存 binding を削除して確認するのは不要な運用リスクになる。

そこで、既存の連携済みアカウントでも確認できる一時診断を追加した。

### 追加した診断

`LORE_AUTH_DIAGNOSTIC_ENTRA_EMAIL_VERIFIED=1` のときだけ、`entra_oid_tid` provider の検証済み ID token から、設定された `email_verified` claim の型と bridge の判定値をログへ出す。

出力する項目:

- provider ID
- claim の型: `missing` / `boolean` / `string` / `other`
- bridge が解釈した `email_verified` の真偽値

この診断には email、Object ID、token 本文、client secret を出力しない。通常のユーザー照合より前に実行するため、既存 binding でログインする場合も観測できる。

### 配置と稼働確認

対象は `172.20.12.193` の `lore-auth-bridge.service`。

サーバー上に残っていたソースの一部は古い版だったため、それをそのままビルド・上書きすることは避けた。稼働バイナリとソースの厳密な対応は確定していないが、稼働開始時刻と同時期のサーバー更新に対応する commit `94c564e` を基点とし、診断のみを追加して Linux release build を作成した。

この commit とローカル HEAD `a751711` の間で、server、adapters、inbound、core のソースに差分がないことも確認した。

- 旧バイナリの退避先: `/home/mgs/lore-auth/backups/entra-email-diagnostic-20261104T1020Z/lore-auth-server`
- systemd drop-in: `/etc/systemd/system/lore-auth-bridge.service.d/90-entra-email-diagnostic.conf`
- drop-in で `LORE_AUTH_DIAGNOSTIC_ENTRA_EMAIL_VERIFIED=1` を設定
- サービス再起動後に `active` とプロセス環境変数を確認
- `https://172.20.12.193:8080/healthz` の HTTP 200 を確認
- 本書作成時点では診断は有効のまま

なお、`41337` は Lore の接続ポートであり、bridge HTTP のログイン先はこの構築では `8080` である。

### 実測結果

既存アカウントでのログイン操作の時間帯に、次の診断行を取得した。

```text
2026-11-04T01:44:24.818204Z INFO lore_auth_adapters::oidc: Entra email_verified diagnostic provider_id=entra email_verified_claim_type="missing" email_verified=false
```

日本時間では 2026-11-04 10:44:24。個人識別子をログへ出していないため、この行単体でログインした人物を特定することはできない。

判明したこと:

- bridge が参照する `email_verified` claim は欠落していた。
- bridge は claim 欠落を `false` として扱う。
- 従って、このログインで得た identity は、現行の verified-email invitation の初回連携条件を満たさない。

判明していないこと:

- 全ユーザー・全ログイン条件で同じ結果になるか。
- claim mapping を含む Entra / bridge の設定全体が適切か。
- email の実際の所有者確認状況。claim 欠落は「未確認と明示された」と同義ではない。

過去の記録にある「`email_verified=false` だった」は、bridge の判定値と、Entra が明示的に返した値を区別して読む必要がある。

### 確認コマンド

193 へ SSH 接続後、保存済みの診断行を表示する:

```bash
sudo journalctl -u lore-auth-bridge.service --since "10 minutes ago" --no-pager -g "Entra email_verified diagnostic" -o cat
```

今後の診断行だけを待ち受ける:

```bash
sudo journalctl -u lore-auth-bridge.service -f -n 0 -g "Entra email_verified diagnostic" -o cat
```

後者は開始前のログを表示しない。終了は `Ctrl+C`。

## 4. Entra 側の設定ミスなのか

今回の欠落だけでは設定ミスと断定できず、「企業向け Entra ID なら本来必ず `email_verified` が出る」とも言えない。

Microsoft の ID token claim reference は、`email` の正確性を保証せず、変更可能であり、認可や永続的なユーザー識別に使わないよう説明している。

`email` scope や optional claim で email の返却を要求することと、その email が確認済みであるという保証を得ることは別である。

Entra での本人認証は成立していても、別途存在する bridge アカウントと email 一致だけで結びつけてよいとは限らない。

## 5. Object ID を識別キーに使う根拠

Microsoft の仕様では、`oid` はユーザーオブジェクトの不変の識別子であり、同じテナントの同じユーザーならアプリケーションをまたいで同じ値になる。再利用されない。`tid` は対象テナントの不変の識別子である。

従って、検証済み ID token の `tid:oid` を bridge の identity に対応づける設計は妥当である。メールの変更に左右されず、アカウントを削除・再作成した場合は別 Object ID として扱える。

ただし、Object ID は秘密ではなく、知っていることは本人認証の証拠にならない。安全性の前提は次のとおり。

1. Entra が発行した ID token を正しく検証する。
2. 受け入れるテナントを限定する。
3. 検証済み token 内の `tid:oid` を使う。
4. 管理者が正しい bridge アカウントに紐づける。

**Object ID を保存する必要性と、管理者に Object ID を手入力させる必要性は別である。**

## 6. Microsoft Graph による登録支援案

### 実現可能な流れ

管理者がユーザーを登録するときに、Microsoft Graph から Entra のユーザー情報を取得し、Object ID の転記作業を置き換えることは可能である。

1. 管理者が UPN（Entra のサインイン名）を入力、またはユーザーを検索する。
2. bridge が対象テナントの Graph API を呼び出す。
3. 表示名、UPN、メールなどの候補情報を管理者が確認する。
4. 取得結果の `id`（Object ID）を使って、bridge ユーザーと `tid:id` を紐づける。

UPN による取得例:

```http
GET https://graph.microsoft.com/v1.0/users/{userPrincipalName}?$select=id,displayName,userPrincipalName,mail
```

### 必要な権限と注意点

- サーバーが app-only で取得する場合、公式 API が示す最小のアプリケーション権限は `User.Read.All`。管理者の同意が必要になる。
- 現在の OIDC ログイン設定があるだけで、Graph API を呼べるとは限らない。Graph 用のアクセストークン取得が必要である。
- UPN とメールは必ずしも一致しない。メール入力を無条件に UPN として扱わない。
- メールで検索する場合、未検出・複数一致を自動的に紐づけず、管理者に確認させる。
- 対象テナントを固定し、取得結果を表示して登録する。Graph のエラー時に手掛かりのない自動登録へ切り替えない。
- ディレクトリの読み取り権限追加は、Entra 管理者・運用担当者と合意してから行う。

これはログイン時に未検証 email を信用する方式ではなく、管理者による事前登録を Graph で支援する方式である。

### 初回登録に Graph を使う場合の懸念と根拠

**Graph で Object ID を取得すること自体が悪いわけではない。取得成功を、その人物の本人認証や bridge ユーザーへの権限付与の承認と同一視することが問題である。**

例えば、作成フォームに入力されたメールでユーザーを検索し、最初の検索結果をそのまま既存ユーザーや権限へ結びつける方式は採用しない。一方、権限を持つ管理者が対象を確認して新しい bridge ユーザーを作る場合、Graph は手入力より転記ミスを減らせる。新規作成の場合も、対象者の選択と付与する権限の承認は必要である。

#### 1. 検索できたことと、本人がログインしたことは別

[Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0) は、ディレクトリにあるユーザー情報を取得する API である。サーバー自身の権限で呼び出す app-only 方式では、対象ユーザーがログインしていなくても情報を取得できる。

従って、取得成功は「その Object ID のユーザー情報が取得できた」という意味であり、「操作中の人がその本人である」という証明ではない。

Graph は登録対象を選ぶために使い、実際のログインでは引き続き Entra の認証を経て、検証済み token の `tid:oid` を照合する。

#### 2. メールで一件見つかっても、登録対象が正しいとは限らない

[ID token 仕様](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference) は、email が変更可能で、正確性を保証しないと説明している。また、Get user で直接指定できるのは Object ID または UPN であり、入力したメールが UPN と同じとは限らない。

検索結果が一件だったとしても、「管理者が登録したかった人物」や「既存の bridge ユーザーに対応する人物」であることまで自動的に確定するわけではない。

そのため、候補を管理者が確認するか、信頼できる社員情報と照合する。メール一致だけを根拠に、既存ユーザーやその権限へ無条件に紐づけない。

#### 3. Object ID の取得のために、アプリの読み取り権限が広がる

Get user / [List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0) の app-only 方式では、最小でも `User.Read.All` が必要になる。実装上は一人の Object ID だけを取得するつもりでも、アプリに付与される読み取り権限がその一人だけに限定されるわけではない。

現在の OIDC ログインに加えて、この権限を bridge に持たせる必要性と影響を評価し、管理者の同意を得る必要がある。管理者のログイン権限を使う委任アクセス方式や、別の運用ツールで取得する方法も比較対象になる。

#### 4. 認証情報やアクセストークンの管理が増える

Graph を呼ぶには、Graph 向けのアクセストークンが必要である。ログインで取得した OIDC の ID token を、そのまま Graph 呼び出しに流用するものではない。

採用する認証方式に応じて、認証情報の保管・更新や、アクセストークンをログなどへ漏らさないための管理が増える。Object ID の転記をなくす利便性だけでなく、この運用負担も導入判断に含める。

#### 5. Graph に問い合わせられないと登録が進まなくなる

Graph を初回登録の必須経路にすると、外部 API の応答に登録処理が依存する。[Graph の throttling 仕様](https://learn.microsoft.com/en-us/graph/throttling) では、要求の制限時に HTTP 429 と `Retry-After` が返る。

そのため、タイムアウト、待機時間を守った再試行、利用者への失敗表示を用意する必要がある。取得に失敗した場合、推測した Object ID やメール一致による登録へ自動的に切り替えてはいけない。

#### 6. 作成・変更直後のユーザー情報が検索に反映されない場合がある

[List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0) は、ユーザーの作成・更新・削除直後には複製遅延があり得ると明記している。

従って、検索で見つからないことを「そのユーザーは存在しない」という確証にはできない。再確認できる手段を用意し、曖昧な検索結果のまま登録を確定しない設計が必要になる。

#### 結論

これらは導入時に評価すべき懸念であり、今回の193で Graph の誤取得・障害を実測したものではない。Graph の利用禁止や、Object ID の目視・手入力を必須とする根拠でもない。

結論として、**「メール入力から無条件に自動紐づけ」は避けるが、「管理者の確認付きで Graph から Object ID を取得して登録する」は妥当な改善候補**である。初回登録の取得処理と、その後の通常ログインは分離し、登録後のログインのたびに Graph 検索を必須にする必要はない。

### 現在の実装状況

Graph によるユーザー検索・Object ID 取得は未実装であり、Entra の API 権限追加も本検証では行っていない。

## 7. 次の判断事項と後片付け

- 手動 Object ID 登録を継続するか、Graph による管理者向け登録支援を実装するかを判断する。
- Graph 案を採用する場合は、app-only / 管理者の委任アクセスの方式、権限、候補選択 UI を決める。
- 診断終了後は、今回追加した drop-in だけを取り除き、`systemctl daemon-reload` と bridge の再起動を行う。他のサービス設定は消さない。
- 必要に応じて退避済みバイナリへ戻す。診断用のソース変更の除去は別途実施する。

## 参考資料

- [Microsoft: ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
- [Microsoft Graph: Get user](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
- [Microsoft Graph: List users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0)
- [Microsoft Graph: Throttling guidance](https://learn.microsoft.com/en-us/graph/throttling)
- [既存の Entra ID 連携の変更根拠](../setup/entra-id-integration-evidence.md)
- [Entra ID 設定手順](../setup/entra-id.md)
- [193 サーバーの構築記録](../setup/on-prem-entra-lore-server.md)
