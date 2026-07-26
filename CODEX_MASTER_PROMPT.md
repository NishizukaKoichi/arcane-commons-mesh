# Codex実装指示書

## Arcane Commons Mesh / 魔法網 v0.1

あなたは、シニア分散システムエンジニア、Rustエンジニア、TypeScriptエンジニア、セキュリティエンジニア、プロダクトデザイナーを兼ねる実装責任者です。

以下の仕様に従い、**一般人が実際に使える共同所有型の分散ストレージMVP**を、設計だけで終わらせず、ローカルで動作確認できる状態まで実装してください。

この指示書は質問票ではありません。仕様に小さな空白がある場合は、最も安全で、単純で、可逆的な判断を選び、`docs/adr/` にADRとして記録して進めてください。破壊的操作、秘密情報の取得、外部へのデプロイ、課金が発生する操作だけは勝手に行わないでください。

---

# 0. 実行前の安全確認

作業開始時に、必ず次を確認してください。

```bash
pwd
git rev-parse --show-toplevel 2>/dev/null || true
git status --short 2>/dev/null || true
ls -la
node --version 2>/dev/null || true
pnpm --version 2>/dev/null || true
rustc --version 2>/dev/null || true
cargo --version 2>/dev/null || true
```

プロジェクトの正本は次の場所にしてください。

```text
/Volumes/Pensive/arcane-commons-mesh
```

ルールは次のとおりです。

- `/Volumes/Pensive` が存在しない場合は停止し、明確なエラーを報告する。
- iCloud、Desktop、Documents、`/tmp`、別のコピーへ自動的にフォールバックしない。
- 既存ディレクトリがある場合は、内容、Git状態、既存の指示ファイルを調査してから変更する。
- 空ならGitリポジトリとモノレポを初期化する。
- `~/.codex/config.toml`、他リポジトリ、無関係な個人ファイルを変更しない。
- 秘密鍵、APIトークン、パスワード、復旧ファイルをGitへコミットしない。
- 勝手にGitHubへpushしない。
- 勝手にCloudflareへデプロイしない。
- 勝手にブロックチェーンへ接続・送信・デプロイしない。

利用可能なら、最初に並列サブエージェントを使って以下を独立にレビューしてください。

1. アーキテクチャと実装順序
2. 暗号・脅威モデル・秘密管理
3. テスト戦略と受入条件

全員の結果を待ち、重複と矛盾を統合して `docs/EXECUTION_PLAN.md` を作成してください。その後、計画だけで止まらず実装を続けてください。

---

# 1. 製品の定義

製品名は次のとおりです。

- 英語名: `Arcane Commons Mesh`
- 日本語名: `魔法網`
- リポジトリ名: `arcane-commons-mesh`
- CLI接頭辞: `acm`
- Rust crate接頭辞: `arcane_mesh_`
- npmスコープ: `@arcane-commons/`

一文での定義:

> 個人が自分のデータと復号鍵を所有し、参加者や地域が持つ余剰ストレージを暗号化して束ね、誰か一社のクラウドに依存せず利用できる、会員制の共同ストレージ網。

このMVPで最も重要な利用価値は次の五つです。

1. 写真、文書、AIの記憶などを一社に人質に取られにくい。
2. 一つの保存拠点が壊れても、別の拠点から復元できる。
3. 余っている保存容量を提供すると、自分が使える共有容量が増える。
4. 保存先の所有者や運営者は、暗号化されたファイルの中身を読めない。
5. サービスを移行しても、復旧ファイルと公開仕様があれば自分のデータを持ち出せる。

---

# 2. 絶対に変えてはならない原則

## 2.1 所有の分離

- データの所有者は、データを預けた本人。
- 復号鍵の所有者も本人。
- 保存機材は、その機材を購入・管理する個人または共同体のもの。
- 接続仕様、データ形式、復元形式は公開仕様にする。
- 運営組織は、利用者のデータを復号できない。
- Cloudflareや将来の別事業者は、交換可能な調整役であり、データの所有者でも唯一の信頼点でもない。

## 2.2 金融化しない

このMVPに暗号通貨を実装してはいけません。

- 売買できるトークンを作らない。
- ウォレット画面を作らない。
- 外部取引所へ送れる資産を作らない。
- クレジットを他人へ送るAPIを作らない。
- クレジットを現金、暗号資産、投票権へ交換できないようにする。
- 利息、投機、価格、チャート、時価総額という概念を導入しない。

内部クレジットは、共同ストレージの物理利用量を調整する**非譲渡の利用単位**に限定します。

## 2.3 人間を点数化しない

- 人間の総合評判スコアを作らない。
- 友情、教育、介護、創作、会話、人格をクレジット化しない。
- ストレージ提供量によって投票権を増やさない。
- 寄付額や保有機材によって発言権を増やさない。
- 投票は一人一票にする。

## 2.4 初版の中央調整を隠さない

v0.1は完全分散型ではありません。

- Cloudflare WorkerとD1を、会員名簿、ノード名簿、配置情報、クレジット台帳、監査記録、提案・投票の調整に使う。
- ただし、ファイル本体、平文ファイル名、復号鍵、回復秘密はCloudflareへ保存しない。
- 調整基盤を別の実装へ交換できるよう、APIとアダプター境界を明確にする。
- すべての重要レコードを利用者または共同体鍵で署名し、管理者がDBを書き換えても検知できるようにする。
- 「完全分散」「絶対安全」「消えない」と表示してはいけない。

---

# 3. v0.1の範囲

## 3.1 必ず実装するもの

1. macOS向けデスクトップアプリ
2. 将来Windows/Linuxでもビルド可能な構成
3. ヘッドレス保存ノードCLI
4. ローカルで3保存ノードを立ち上げるデモ環境
5. ファイルのローカル暗号化
6. ストリーミング分割
7. 暗号化チャンクの3重複製
8. 一台停止時の復元
9. 改ざんチャンクの検出と拒否
10. 復旧ファイルのエクスポートと復元
11. 会員制コミュニティの作成、招待申請、管理者承認
12. 保存拠点の登録、容量設定、開始・停止
13. 非譲渡の共有容量クレジット
14. 一人一票の簡易提案・投票
15. 追記型監査ログと日次Merkle root
16. 将来のブロックチェーン固定用インターフェース
17. Cloudflare Worker + D1の調整API
18. OpenAPI仕様
19. 自動テスト、CI、ローカルデモスクリプト
20. 脅威モデル、運用手順、復旧手順

## 3.2 v0.1では実装しないもの

- 公開・匿名の誰でも参加できるストレージ網
- 暗号通貨
- 売買可能トークン
- スマートコントラクト
- EVM mainnet/testnetへの実接続
- GPUやCPU計算資源の共有
- AI推論ジョブ
- モバイルアプリ
- スマホのバックグラウンド保存ノード化
- Byzantine consensus
- 独自ブロックチェーン
- erasure coding
- cross-user deduplication
- 公開ファイル共有リンク
- 完全匿名化
- 法的本人確認
- 一人一アカウントを世界規模で保証する仕組み
- 本番のセキュリティ監査済みという主張

これらは `docs/ROADMAP.md` に将来項目として整理してください。

---

# 4. 技術スタック

依存バージョンは、実装時点で利用可能な安定版を調査し、lockfileへ固定してください。無制限な `latest` 指定は使わないでください。

## 4.1 モノレポ

- `pnpm` workspace
- Cargo workspace
- TypeScript strict mode
- Rust stable
- Git

## 4.2 デスクトップ

- Tauri 2
- React
- Vite
- TypeScript
- Zod
- React Testing Library
- Vitest
- Tauri Stronghold plugin

## 4.3 P2P通信

- Rustの`iroh`を使用する。
- QUICベースの直接接続を優先する。
- 直接接続できない場合は暗号化relayへフォールバックできる構造にする。
- 開発時の既定relayは開発用途に限定する。
- 本番向けには自己ホストrelay URLを設定可能にする。
- ローカルLANだけでも動作するデモ経路を用意する。
- CIのテストは外部ネットワークに依存しないin-memory transportでも実行できるようにする。

## 4.4 暗号

Rust側で以下を使用する。

- `chacha20poly1305` の XChaCha20-Poly1305
- `blake3`
- `ed25519-dalek`
- `argon2`
- `rand_core`
- `zeroize`
- OS乱数

独自暗号アルゴリズムを作らないでください。

## 4.5 ローカル保存

- 暗号化された保管庫カタログ
- 保存ノード用のSQLiteメタデータDB
- オブジェクト本体はcontent-addressed file layout
- 一時ファイルへ書いて検証後にatomic rename

## 4.6 調整API

- Cloudflare Workers
- Hono
- Cloudflare D1
- Wrangler
- Zod
- OpenAPI生成

R2を利用者ファイルの保存先に使ってはいけません。v0.1では、R2を必須依存にしないでください。

## 4.7 公開サイト

- Astro
- TypeScript
- Cloudflare Pages対応
- 製品説明、ダウンロード案内、公開仕様、システム状態の表示だけを行う。
- 認証済みの秘密操作はデスクトップアプリ側に置く。

---

# 5. リポジトリ構成

最低限、次の構造にしてください。

```text
arcane-commons-mesh/
├── AGENTS.md
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── package.json
├── pnpm-workspace.yaml
├── Cargo.toml
├── rust-toolchain.toml
├── .nvmrc
├── .gitignore
├── .env.example
├── apps/
│   ├── desktop/
│   │   ├── src/
│   │   └── src-tauri/
│   ├── api/
│   └── site/
├── crates/
│   ├── mesh-core/
│   ├── mesh-node/
│   ├── mesh-cli/
│   ├── mesh-protocol/
│   └── mesh-testkit/
├── packages/
│   ├── contracts/
│   ├── ui/
│   └── config/
├── infra/
│   └── cloudflare/
├── scripts/
│   ├── demo-up.*
│   ├── demo-down.*
│   └── verify-mvp.*
├── fixtures/
├── docs/
│   ├── PRODUCT_SPEC.md
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── RECOVERY.md
│   ├── OPERATIONS.md
│   ├── PROTOCOL.md
│   ├── CREDIT_POLICY.md
│   ├── GOVERNANCE.md
│   ├── PRIVACY.md
│   ├── ROADMAP.md
│   ├── EXECUTION_PLAN.md
│   └── adr/
└── .github/
    └── workflows/
```

ライセンスは所有者の法的・事業的判断を伴うため、Codexが勝手に選ばないでください。`LICENSE`を自動作成せず、`docs/adr/0001-license-decision-required.md`にApache-2.0、MPL-2.0、AGPL-3.0の違いと、この製品に与える影響を整理し、未決定として残してください。

`AGENTS.md` には、少なくとも次を簡潔に記述してください。

- 正本パスとiCloudへフォールバックしない規則
- リポジトリ構造
- build/test/lint/typecheckコマンド
- 暗号と秘密管理の禁止事項
- Cloudflareにファイル本体を置かない規則
- クレジットを金融化しない規則
- 変更後に必ず実行する検証
- 「完了」の定義

---

# 6. ドメインモデル

## 6.1 Identity

各利用者はローカルで次を生成します。

- `identity_signing_key`: Ed25519
- `identity_public_key`
- `vault_master_key`: 32 bytes random

秘密情報はTauri Strongholdへ保存してください。

利用者IDは公開鍵から導出した安定IDにしてください。メールアドレスを主キーにしないでください。

## 6.2 Community

コミュニティには次があります。

- `community_id`
- `name`
- `community_root_public_key`
- `created_at`
- `policy_version`
- `status`

最初の作成者だけが、ローカルに`community_root_private_key`を持ちます。サーバーへ送信してはいけません。

最初の作成時には、作成者のMembershipCredentialをcommunity root keyで自己発行し、community public key、作成者公開鍵、署名をまとめてbootstrap proofとしてAPIへ登録してください。


## 6.3 MembershipCredential

会員資格は、共同体のroot keyで署名された資格情報です。

最低限のフィールド:

```text
credential_version
community_id
member_public_key
member_id
roles
issued_at
expires_at
serial
issuer_public_key
signature
```

v0.1の加入手順:

1. 管理者が期限付き招待コードを発行する。
2. 新規利用者がローカルでidentity keyを作る。
3. 招待コードと公開鍵を使ってjoin requestを送る。
4. 管理者のデスクトップアプリに承認待ちとして表示する。
5. 管理者が承認すると、管理者端末が資格情報へ署名する。
6. 署名済み資格情報をAPIへ登録し、新規利用者へ返す。

Cloudflare Workerがcommunity root private keyを持ってはいけません。

## 6.4 NodeCertificate

保存ノードは、利用者identityから分離したEd25519 endpoint keyを持ちます。

ノード証明には次を含めます。

```text
node_id
community_id
owner_member_id
endpoint_public_key
allowed_roles
max_storage_bytes
issued_at
expires_at
signature_by_member_identity
```

ノード鍵が漏れても、利用者の保管庫を復号できない構造にしてください。

## 6.5 Vault

各利用者に一つ以上の保管庫を許可します。

```text
vault_id
owner_member_id
community_id
latest_catalog_cid
catalog_version
signed_at
owner_signature
```

D1には、暗号化カタログのCID、バージョン、署名だけを置きます。平文のファイル名やパスを置いてはいけません。

## 6.6 StorageObject

保存ノードが保管するのは、意味を知らない暗号化blobです。

```text
object_cid
ciphertext_size
object_kind: data_chunk | encrypted_manifest | encrypted_catalog
replica_target
created_at
retention_until
```

---

# 7. ファイル暗号化と分割仕様

## 7.1 ストリーミング

- ファイル全体をメモリへ読み込まない。
- 既定チャンクサイズは4 MiB。
- 大きなファイルでも一定メモリで処理する。
- 最終チャンクは64 KiB境界までランダムpaddingできるようにする。
- padding長は暗号化メタデータに入れる。

## 7.2 ファイル鍵

各ファイルの各バージョンごとに、ランダムな32-byte `file_key` を生成します。

各チャンクはXChaCha20-Poly1305で暗号化します。

各チャンクに一意な24-byte nonceを使用してください。nonce再利用は禁止です。

AADには最低限、次を含めてください。

```text
protocol_version
vault_id
file_version_id
chunk_index
plaintext_length
```

## 7.3 CID

CIDは、保存する暗号化blob全体のBLAKE3 hashから作ります。

保存ノードは、受信後にCIDを再計算し、一致しないblobを拒否します。

## 7.4 EncryptedFileManifest

ファイルmanifestの平文には次を含めます。

```text
manifest_version
file_id
file_version_id
relative_path
file_name
mime_type
plaintext_size
plaintext_hash
modified_at
created_at
file_key
ordered_chunk_cids
chunk_plaintext_lengths
padding_lengths
```

manifest全体を`vault_master_key`から導出した鍵で暗号化します。

manifestの暗号化blobも通常の保存オブジェクトとして扱い、既定で5複製してください。

## 7.5 EncryptedVaultCatalog

カタログには、ファイル一覧、バージョン、削除tombstone、最新manifest CIDを含めます。

- カタログは暗号化する。
- 所有者identity keyで署名する。
- 最新カタログCIDだけをD1へ登録する。
- カタログの古い版も保持し、少なくとも30日復元可能にする。

## 7.6 重複排除

v0.1ではcross-user deduplicationを実装しません。プライバシーを優先します。

---

# 8. 保存ノード仕様

## 8.1 保存範囲

保存ノードは、利用者が明示的に選択した専用ディレクトリ以外を読み書きしてはいけません。

- ホームディレクトリを走査しない。
- シンボリックリンクを追跡しない。
- path traversalを拒否する。
- 保存上限を超えて書かない。
- 最低空き容量を設定可能にする。

## 8.2 オブジェクト配置

```text
<storage-root>/objects/<first-two-cid-chars>/<cid>.blob
```

書き込み手順:

1. 一時ファイルへストリーミング受信
2. サイズ上限確認
3. BLAKE3検証
4. fsync
5. atomic rename
6. SQLiteへmetadata記録
7. control planeへplacement成功を署名報告

## 8.3 既定設定

- 提供容量: 10 GiB
- 最大受信速度: 5 MiB/s、UIから変更可能
- heartbeat: 60秒
- 5分heartbeatなしで`degraded`
- 24時間offlineでrepair候補
- 保存ノードは手動で開始・停止可能
- OS起動時自動起動はopt-in

## 8.4 P2Pプロトコル

ALPNまたはprotocol identifier:

```text
arcane-commons-mesh/1
```

最低限の操作:

```text
HELLO
HAS_OBJECT
PUT_OBJECT
GET_OBJECT
AUDIT_OBJECT
DELETE_AFTER
REPLICATE_OBJECT
PING
```

- 全メッセージにprotocol versionを入れる。
- app-level authorizationとしてMembershipCredentialとNodeCertificateを検証する。
- フレームサイズ上限を設ける。
- backpressureを実装する。
- タイムアウトとキャンセルを実装する。
- リモートから受け取ったファイルパスを使用しない。

---

# 9. 複製・復元・修復

## 9.1 複製数

- data chunk: target 3
- encrypted manifest: target 5
- encrypted catalog: target 5
- 最低復元可能数は1だが、UI上の安全状態はtarget達成時だけ「安全」と表示する。

## 9.2 配置選択

可能な範囲で次を分散してください。

- 異なるnode_id
- 異なるowner_member_id
- 異なるfailure_domain
- 異なる地域タグ

一人が多数ノードを持っても、同一障害領域として扱えるようにしてください。

## 9.3 復元

復元時は、利用可能なplacementを順に試し、受信した暗号化blobのCIDを検証します。

- 不一致ならそのplacementを不正として記録する。
- 別の複製へ自動的に切り替える。
- 復号後にplaintext hashも検証する。
- 元の相対パスを安全に再構築する。
- 既存ファイルを勝手に上書きせず、確認または安全な別名を使う。

## 9.4 修復

control planeは不足複製を検出してrepair taskを作成します。

- 健全なsource nodeから新しいdestination nodeへ、暗号化blobのまま複製する。
- ownerがonlineでなくても修復できる。
- sourceもdestinationも中身を復号できない。
- 完了後にCIDを検証し、placementを更新する。
- すべてのrepair eventを監査ログへ残す。

v0.1では、D1上のrepair task tableとノードのpollingでよいです。将来Cloudflare Queuesへ置換できるアダプター境界を作ってください。

---

# 10. 監査

## 10.1 目的

「保存していると申告しただけ」でクレジットを得られないようにします。

## 10.2 Auditor node

コミュニティ内の一つ以上のノードを`auditor` roleにできます。

監査手順:

1. control planeがランダムなobject CIDと保存nodeを選ぶ。
2. auditor nodeへaudit taskを発行する。
3. auditorが保存nodeから暗号化blobを取得する。
4. BLAKE3でCIDを検証する。
5. 内容は復号せず破棄する。
6. auditorが結果へ署名する。
7. APIが結果を記録する。

既定:

- 各保存nodeについて6時間ごとに最低1件
- または保存object数の1%/日
- 直近24時間に成功監査がないnodeは新規配置対象から外す

これは厳密なproof-of-retrievabilityではありません。UIと文書で誤認させないでください。

---

# 11. 共有容量クレジット

画面上の名称は「共有容量」にしてください。技術文書では`Storage Credit`を使用できます。

## 11.1 単位

内部単位:

```text
1 credit = 1 GiB-hour of physical replicated storage
```

浮動小数点を使わず、整数の`milli_gib_hour`で記録してください。

1 GiBの論理データを3重複製で1時間保持すると、3 credit消費します。

## 11.2 基礎利用枠

全会員に毎月、5 GiBの論理データを3重複製で30日保持できる相当量を無条件付与します。

これは内部では、概ね次に相当します。

```text
5 GiB × 3 replicas × 30 days × 24 hours
```

基礎利用枠は翌月へ繰り越しません。

## 11.3 提供による獲得

保存nodeが、監査済みの暗号化blobを実際に保持していた時間に応じて獲得します。

- 自己申告だけでは加算しない。
- 直近24時間以内の成功監査が必要。
- 失敗監査期間は加算を停止する。
- 獲得分は90日で失効する。
- 月間獲得上限を設定可能にする。

## 11.4 不足時

クレジット不足を理由に即座にデータを削除してはいけません。

- 新規アップロードを停止する。
- 既存データは最低30日保護する。
- エクスポートと復元手段を提示する。
- UIに不足理由と必要量を明確に表示する。

## 11.5 禁止API

次のAPI、画面、操作を作ってはいけません。

```text
transfer credit
sell credit
buy credit
withdraw credit
deposit token
exchange credit
stake credit
```

テストで、クレジット移転APIが存在しないことを保証してください。

---

# 12. ガバナンス

v0.1では簡易的な一人一票だけを実装します。

## 12.1 Proposal

```text
proposal_id
community_id
title
body
created_by_member_id
created_at
opens_at
closes_at
quorum_percent
threshold_percent
status
```

## 12.2 Vote

```text
proposal_id
member_id
choice: yes | no | abstain
cast_at
member_signature
```

ルール:

- active membership一件につき一票。
- 重複投票は最後の一票へ更新可能だが、履歴は監査ログに残す。
- ストレージ提供量、クレジット残高、寄付額で重み付けしない。
- 既定quorum 20%。
- 既定thresholdはyes/no有効票の過半数。
- v0.1では提案結果を自動で危険なシステム変更へ反映しない。
- 設定変更は管理者が確認して実施し、監査ログへ残す。

---

# 13. 復旧仕様

## 13.1 Recovery Kit

利用者はオンボーディング中に、必ず暗号化復旧ファイルを保存します。

拡張子:

```text
.acm-recovery
```

内容:

```text
format_version
created_at
identity_seed
vault_master_key
optional_community_authority_keys
community_ids
control_plane_urls
public_metadata
checksum
```

秘密部分全体を、利用者が入力した復旧パスフレーズからArgon2idで導出した鍵によりXChaCha20-Poly1305で暗号化してください。

- KDF saltはランダム。
- KDF parameterをheaderへ保存。
- 最低64 MiB memory costを使う。
- 復旧ファイルをログへ出さない。
- 復旧パスフレーズを保存しない。
- clipboardへ自動コピーしない。

## 13.2 復旧テスト

E2Eで次を検証してください。

1. 新規利用者を作る。
2. ファイルを保存する。
3. Recovery Kitを出力する。
4. ローカルidentity、Stronghold、catalog cacheを削除した隔離テスト環境を作る。
5. Recovery Kitとパスフレーズからidentityとvaultを復元する。
6. control planeから最新catalog CIDを取得する。
7. meshからcatalog、manifest、chunksを取得する。
8. 元ファイルとhash一致することを確認する。

## 13.3 将来項目

guardian recovery、Shamir secret sharing、複数端末承認はv0.1では実装せず、roadmapへ記載してください。

---

# 14. 削除と保持

- 通常削除はcatalogにtombstoneを作る。
- 既定保持期間は30日。
- 保持期間中は旧versionから復元できる。
- 保持期間後、参照がなくなったobjectにGC taskを作る。
- ノードはcontrol planeの署名付き削除指示を確認してから削除する。
- 「即時完全消去」と表示してはいけない。
- 永久削除ではfile keyをcatalogから除去し、暗号学的消去を行う。
- 暗号化blobが物理ノードにGCまで残る可能性をUIと文書で説明する。

---

# 15. Control Plane API

APIは`/v1`でversioningしてください。

最低限、次のendpointを実装します。

## 15.1 Session / challenge

```text
POST /v1/auth/challenges
POST /v1/auth/sessions
DELETE /v1/auth/sessions/current
```

- challengeはランダム、単回使用、5分で失効。
- clientはidentity keyで署名する。
- session tokenは短命、既定15分。
- refreshは再署名を要求する。
- replay nonceをD1で拒否する。

## 15.2 Community and membership

```text
POST /v1/communities
GET  /v1/communities/:communityId
POST /v1/communities/:communityId/invites
POST /v1/communities/:communityId/join-requests
GET  /v1/communities/:communityId/join-requests
POST /v1/communities/:communityId/join-requests/:requestId/approve
GET  /v1/communities/:communityId/members
POST /v1/communities/:communityId/members/:memberId/revoke
```

承認endpointは、管理者端末が作った署名済みMembershipCredentialを受け取る形にしてください。

## 15.3 Nodes

```text
POST /v1/nodes
POST /v1/nodes/:nodeId/heartbeat
GET  /v1/nodes/:nodeId
GET  /v1/nodes/candidates
POST /v1/nodes/:nodeId/disable
```

## 15.4 Vault/catalog

```text
PUT /v1/vaults/:vaultId/catalog-pointer
GET /v1/vaults/:vaultId/catalog-pointer
```

保存するのはCID、version、timestamp、owner signatureのみです。

## 15.5 Objects and placements

```text
POST /v1/objects
GET  /v1/objects/:cid
POST /v1/objects/:cid/placements
GET  /v1/objects/:cid/placements
POST /v1/placements/:placementId/failed
```

## 15.6 Repair and audit tasks

```text
GET  /v1/nodes/:nodeId/tasks
POST /v1/tasks/:taskId/accept
POST /v1/tasks/:taskId/complete
POST /v1/tasks/:taskId/fail
```

## 15.7 Credits

```text
GET /v1/credits/me
GET /v1/credits/me/entries
GET /v1/communities/:communityId/credit-policy
```

移転、購入、売却endpointを作らないでください。

## 15.8 Governance

```text
POST /v1/communities/:communityId/proposals
GET  /v1/communities/:communityId/proposals
GET  /v1/proposals/:proposalId
PUT  /v1/proposals/:proposalId/vote
GET  /v1/proposals/:proposalId/result
```

## 15.9 Audit anchors

```text
GET  /v1/communities/:communityId/audit-events
GET  /v1/communities/:communityId/audit-anchors
POST /v1/internal/audit-anchors/run
```

internal endpointはローカルまたはcronからのみ呼べるようにしてください。

---

# 16. D1データモデル

migrationを作成してください。最低限のtable:

```text
communities
members
membership_credentials
invites
join_requests
nodes
node_heartbeats
vault_catalog_pointers
objects
placements
node_tasks
credit_accounts
credit_entries
credit_grants
credit_policies
proposals
votes
auth_challenges
sessions
audit_events
audit_anchors
replay_nonces
```

要件:

- すべてUTC timestamp。
- 金額やクレジットにfloatを使わない。
- unique constraintを正しく設ける。
- active memberのproposalごとのvoteは一件。
- CIDとpublic keyはformat validationする。
- 監査イベントはhash chainを持つ。
- file name、relative path、file key、vault master key、plaintext contentを保存するcolumnを作らない。

テストでD1 exportまたはrepository mockを走査し、fixtureの平文ファイル名と平文内容が存在しないことを確認してください。

---

# 17. 追記型監査ログ

各重要操作を監査イベントにします。

例:

```text
community_created
join_requested
membership_approved
membership_revoked
node_registered
node_disabled
object_registered
placement_created
placement_failed
audit_succeeded
audit_failed
repair_started
repair_completed
credit_granted
credit_earned
credit_consumed
proposal_created
vote_cast
catalog_pointer_updated
```

イベントhash:

```text
event_hash = BLAKE3(previous_event_hash || canonical_event_bytes)
```

日次でイベントhash群のMerkle rootを作り、`audit_anchors`へ保存します。

アダプター境界:

```text
AuditAnchorAdapter
- LocalFileAnchor
- D1Anchor
- MockAnchor
- FutureEvmAnchor
```

`FutureEvmAnchor`はinterface、型、mock testだけを用意し、RPC接続、wallet、秘密鍵、contractを実装しないでください。

---

# 18. UI/UX

既定言語は日本語、英語切替を用意してください。

一般利用者の画面では、技術語をできるだけ隠します。

表示語:

- Node → 保存拠点
- Storage Credit → 共有容量
- Replica → 安全な複製
- Vault → 保管庫
- Recovery Kit → 復旧ファイル
- Auditor → 確認拠点

最低限の画面:

## 18.1 Onboarding

1. 「自分の保管庫を作る」
2. 復旧パスフレーズ設定
3. 復旧ファイル保存
4. 新しい共同体を作る、または招待コードで参加申請
5. 承認待ち状態

復旧ファイルを保存するまで、完了扱いにしないでください。

## 18.2 Dashboard

- 使用中の論理容量
- 実際の物理複製容量
- 安全な複製 `3/3` 等
- 最終バックアップ
- 保存拠点の接続状態
- 今月の基礎共有容量
- 提供で得た共有容量
- 警告と修復状態

## 18.3 Vault

- drag and drop追加
- フォルダ追加
- upload進捗
- ファイル一覧
- version履歴
- restore
- delete
- safety status

## 18.4 Provide Storage

- 提供ON/OFF
- 専用フォルダ選択
- 提供上限
- 最低空き容量
- 帯域上限
- 自動起動opt-in
- 保存中の暗号化容量
- 直近監査結果

## 18.5 Community

- 会員一覧
- 加入申請
- 承認・拒否
- 保存拠点一覧
- 提案一覧
- 投票

## 18.6 Recovery and settings

- 復旧ファイル再出力
- relay設定
- API URL
- 言語
- diagnostics export
- account lock

デザイン要件:

- 落ち着いた魔法的世界観。ただし可読性を優先する。
- 装飾より情報階層を優先する。
- keyboard navigation。
- WCAG AA相当のcontrast。
- destructive actionは確認する。
- 秘密鍵や復旧秘密を通常画面に表示しない。
- 「分散」「ブロックチェーン」を売り文句の中心にしない。
- 一般人には「消えにくい」「移せる」「読まれにくい」を伝える。

---

# 19. セキュリティ要件

`docs/THREAT_MODEL.md`に、少なくとも以下を記述し、対応状況を表にしてください。

攻撃者:

- 悪意ある保存node
- 侵害されたcontrol plane管理者
- 盗まれた端末
- 改ざんされたchunk
- replay attacker
- 招待コード総当たり
- path traversal attacker
- symlink attacker
- quota exhaustion attacker
- 悪意あるcommunity member
- 複数nodeの共謀

必須対策:

- client-side encryption
- per-file version key
- unique nonce
- signed membership
- signed node certificate
- signed catalog pointer
- signed votes
- short-lived session
- replay protection
- rate limit
- CID verification
- plaintext hash verification
- atomic writes
- path normalization
- symlink rejection
- quota enforcement
- size limits
- timeout and cancellation
- secret redaction
- zeroize sensitive buffers where practical
- no `unsafe` Rust unlessADRと安全性説明がある
- dependency audit

ログへ絶対に出してはいけないもの:

- file content
- plaintext file name
- relative path
- file key
- vault master key
- identity private key
- recovery passphrase
- recovery kit content
- session token
- invite code raw value

Support bundleは秘密を除外し、収集前に内容一覧を利用者へ見せてください。

---

# 20. 削除・退会・運営停止への耐性

## 20.1 会員失効

- 失効後は新規保存を停止。
- 既存データのexport猶予を既定30日設ける。
- 即時削除しない。
- 失効操作と期限を監査ログへ残す。

## 20.2 保存node離脱

- node所有者はいつでも提供停止できる。
- 可能なら停止前にdrainを実行し、別nodeへ複製する。
- 強制停止でも、control planeが不足複製を検出する。

## 20.3 Control plane移行

次を実装してください。

```text
acmctl community export-snapshot
acmctl community verify-snapshot
```

snapshotに含めるもの:

- community public data
- active member public keys and credentials
- node certificates
- signed catalog pointers
- audit chain and anchors
- credit policy and signed ledger entries
- proposals and signed votes

ファイル本体や復号鍵は含めません。

snapshotは別control plane実装でimport可能なversioned JSON/CBOR仕様にしてください。

---

# 21. CLI

最低限、次を実装してください。

```text
acmctl doctor
acmctl identity create
acmctl recovery export
acmctl recovery import
acmctl community create
acmctl community join-request
acmctl community approve-member
acmctl community export-snapshot
acmctl community verify-snapshot
acmctl vault create
acmctl vault add <path>
acmctl vault list
acmctl vault restore <file-id> --output <path>
acmctl vault verify
acmctl node init
acmctl node run
acmctl node status
acmctl demo seed
```

CLIはデスクトップと同じ`mesh-core`を使用し、別実装を複製しないでください。

---

# 22. ローカルデモ

一つのコマンドで、次を起動できるようにしてください。

```bash
pnpm demo:up
```

起動対象:

- ローカルWorker + D1
- community bootstrap
- member Alice
- member Bob
- storage node A
- storage node B
- storage node C
- auditor node

データディレクトリはリポジトリ配下の`.demo/`に隔離し、`.gitignore`してください。

終了:

```bash
pnpm demo:down
```

完全検証:

```bash
pnpm verify:mvp
```

`verify:mvp`は次を自動実行してください。

1. ランダムfixtureを作成。
2. Aliceのvaultへ追加。
3. 3 nodeへ複製されたことを確認。
4. 元fixtureを隔離。
5. node Bを停止。
6. restoreしてhash一致を確認。
7. node Cの一つのblobを故意に改ざん。
8. 改ざんを検出し、健全な複製から復元できることを確認。
9. node Aの提供クレジットが増えたことを確認。
10. Aliceの利用クレジットが消費されたことを確認。
11. credit transfer endpointが存在しないことを確認。
12. 同一memberの二重投票が二票として数えられないことを確認。
13. Recovery Kitから隔離環境で復元する。
14. D1とnode storageを走査し、fixtureの平文file nameと平文contentが存在しないことを確認。
15. audit hash chainとMerkle rootを検証。

外部インターネットなしで成功する経路を用意してください。

---

# 23. テスト

## 23.1 Rust unit tests

最低限:

- encrypt/decrypt round trip
- nonce uniqueness guard
- wrong key failure
- modified ciphertext failure
- modified AAD failure
- chunk streaming boundaries
- large file constant-memory behavior
- CID calculation
- manifest encryption
- catalog signature
- membership credential verification
- node certificate verification
- recovery file round trip
- corrupted recovery file rejection
- path traversal rejection
- symlink rejection
- quota enforcement
- atomic write recovery
- credit integer arithmetic
- audit hash chain
- Merkle root determinism

## 23.2 TypeScript tests

- Zod validation
- API auth challenge
- replay rejection
- expired challenge rejection
- unauthorized role rejection
- duplicate vote handling
- no credit transfer route
- D1 migrations
- plaintext absence checks
- UI state and error messages

## 23.3 Integration tests

- 3-node replication
- one-node outage restore
- corrupted replica fallback
- repair task
- auditor verification
- recovery from clean environment
- control plane snapshot export/verify

## 23.4 UI tests

- onboarding cannot finish without Recovery Kit export
- destructive delete confirmation
- provider path selection required
- quota warning
- offline/degraded status
- accessibility smoke test

---

# 24. コマンド

root `package.json`から最低限、次を実行可能にしてください。

```bash
pnpm install
pnpm dev
pnpm lint
pnpm format:check
pnpm typecheck
pnpm test
pnpm test:integration
pnpm build
pnpm demo:up
pnpm demo:down
pnpm verify:mvp
```

Rust側:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
```

依存監査:

```bash
pnpm audit --audit-level=high
cargo audit
```

`cargo audit`が未導入なら、CIで導入するか、再現可能な手順を用意してください。

---

# 25. GitHub Actions

最低限、次のworkflowを作成してください。

## `ci.yml`

- checkout
- pinned Node setup
- pnpm cache
- Rust stable setup
- `pnpm install --frozen-lockfile`
- lint
- format check
- typecheck
- unit tests
- Rust fmt
- Rust clippy
- Rust tests
- build
- dependency audit

## `integration.yml`

- Linux上でlocal control planeと複数nodeを起動
- `pnpm verify:mvp`
- 失敗時に秘密を含まないdiagnostic artifactを保存

## `desktop-build.yml`

- macOSでTauri app build
- signingなしのdevelopment artifact
- secrets不要
- release publishはしない

## `deploy-cloudflare.yml`

- `workflow_dispatch`のみ
- environment approval前提
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- D1 database ID
- custom domainへ接続しない
- main pushで勝手にdeployしない

GitHub Actionsの参照は、可能な限りmajor tagではなく安全な固定方法を選び、理由をADRへ記録してください。

---

# 26. Cloudflare設定

`wrangler.toml`または対応する設定に、次を用意してください。

- compatibility dateを実装日の値へ固定
- D1 binding
- local D1 migration
- scheduled cron for audit/repair/credit accounting
- dev/prod environment分離
- secretsはbinding名だけ記載

`.env.example`には名前だけを記載し、実値を入れないでください。

例:

```text
SESSION_SIGNING_SECRET=
CONTROL_PLANE_BASE_URL=
CLOUDFLARE_ACCOUNT_ID=
CLOUDFLARE_API_TOKEN=
D1_DATABASE_ID=
```

Community root key、identity key、vault keyをCloudflare secretとして置いてはいけません。

---

# 27. 実装順序

以下の順で進めてください。各段階でテストを追加し、壊れた状態を長く残さないでください。

## Milestone 1: Foundation

- repo scaffold
- AGENTS.md
- docs skeleton
- CI skeleton
- shared contracts
- local config

## Milestone 2: Core cryptography and local storage

- identity
- Stronghold integration
- recovery file
- chunk encryption
- encrypted manifest/catalog
- content-addressed local store
- unit tests

## Milestone 3: Local multi-node mesh

- iroh transport
- node certificates
- put/get/has
- 3-node replication
- restore
- corruption fallback
- in-memory transport for tests

## Milestone 4: Control plane

- D1 migrations
- auth challenge/session
- communities/membership
- node registry
- object/placement registry
- signed catalog pointer
- OpenAPI

## Milestone 5: Credits, audit, repair

- auditor role
- audit task
- credit ledger
- repair tasks
- grace policy
- audit hash chain and daily root

## Milestone 6: Desktop UX

- onboarding
- Recovery Kit flow
- vault UI
- provider UI
- community UI
- governance UI
- diagnostics

## Milestone 7: End-to-end verification

- demo scripts
- verify:mvp
- CI integration
- security review
- documentation

## Milestone 8: Final review

利用可能なら、並列サブエージェントで次をレビューしてください。

- security risks
- data-loss risks
- privacy leaks
- test gaps
- maintainability

全結果を待ち、重大・高リスク項目を修正してから完了報告してください。

---

# 28. 受入条件

以下がすべて真になるまで、完了と報告してはいけません。

1. `/Volumes/Pensive/arcane-commons-mesh`が正本である。
2. `pnpm lint`が成功する。
3. `pnpm format:check`が成功する。
4. `pnpm typecheck`が成功する。
5. `pnpm test`が成功する。
6. `cargo fmt --check`が成功する。
7. `cargo clippy ... -D warnings`が成功する。
8. `cargo test --workspace`が成功する。
9. `pnpm build`が成功する。
10. `pnpm verify:mvp`が成功する。
11. 3重複製が確認できる。
12. 一台停止でも復元できる。
13. 改ざんblobを受け入れない。
14. 復旧ファイルからclean environmentへ復元できる。
15. D1に平文file name、path、content、file keyが存在しない。
16. 保存nodeに平文contentが存在しない。
17. control plane管理者だけでは復号できない。
18. credit transfer機能が存在しない。
19. storage creditで投票権が増えない。
20. 一人一票がテストされている。
21. 実ブロックチェーン接続が存在しない。
22. 秘密情報がGitにない。
23. 外部deployを行っていない。
24. `docs/THREAT_MODEL.md`が現状を正直に記述している。
25. READMEだけで第三者がローカルデモを再現できる。

---

# 29. 完了時の報告形式

最後に、次の順で報告してください。

1. 実装したもの
2. 主要アーキテクチャ
3. 作成・変更した主要ファイル
4. 実行したコマンド
5. テスト結果
6. `verify:mvp`の結果
7. 残っている制約と既知リスク
8. 本番利用前に必要な独立セキュリティ監査項目
9. デプロイに必要だが、まだ設定していないsecrets
10. 次に着手すべき一つの作業

「完成」「安全」「完全分散」と誇張しないでください。v0.1は、**会員制・暗号化・共同保存の実証可能なMVP**として報告してください。

---

# 30. 今すぐ開始する

まず作業ディレクトリと環境を検証し、`docs/EXECUTION_PLAN.md`を作成してください。そのままMilestone 1から実装を開始し、受入条件を満たすまで継続してください。

質問は、次の場合だけ行ってください。

- `/Volumes/Pensive`が存在しない。
- 既存リポジトリに未コミットの競合変更があり、安全に進められない。
- 秘密情報や有料外部サービスへのアクセスが不可欠になった。
- 外部deploy、GitHub push、ブロックチェーン接続が必要になった。

それ以外は、安全で可逆的な既定値をADRへ記録し、実装を進めてください。
