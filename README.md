# Midnight-blocklog (English)

A tool for Midnight nodes that **displays the Aura block production schedule and records it in SQLite**.

※This tool is currently in beta. Specifications may change and backward-incompatible changes may occur before the official release.

This tool **auto-detects the Aura public key** from the node keystore, verifies that **this node holds the corresponding secret key** via `author_hasKey`, then calculates and records the assigned slots for the current session (referred to as “epoch” here for convenience).

## What it does

- Calculates your **assigned Aura slots** in the current epoch (session), displays them, and stores them in SQLite as `schedule`
- In watch mode (`mblog block --watch`), tracks the chain and updates the status. It waits until the next session, and at the boundary it calculates and stores the assigned slots for the new epoch.
  - `schedule` (planned)
  - `mint` (observed on best head)
  - `finality` (observed on finalized)
- Stores Authority set information per epoch (hash/length, start/end slots, etc.)
- Supports output timezone selection and colored output (auto-detected via TTY)

## Requirements

- `midnight-node` must be started with the following flags (WS RPC enabled
  `--rpc-methods=Unsafe`
  `--unsafe-rpc-external`
  `--rpc-port 9944`
- Rust (`cargo`) build environment

## Install Rust (rustup)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable
rustup default stable
rustc -V
cargo -V
```

## Build dependencies (Linux)
Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
```

## Install (clone this repository and run `cargo install`)

```bash
git clone https://github.com/btbf/Midnight-blocklog.git
cd Midnight-blocklog
git checkout <latest_tag_name>
cargo install --path . --bin mblog --locked --force
```

`mblog` is typically installed to `~/.cargo/bin/mblog`.

## Usage

### 1) Show help

```bash
mblog --help
```

Output (actual `--help`):

```text
Usage: mblog <COMMAND>

Commands:
  block  Show Aura slot schedule (use --watch to monitor)
  log    Show stored blocks from SQLite
```

## Options

Options are provided per subcommand.

### `mblog block`

- `--ws <WS>`: WS RPC endpoint (optional; default: `ws://127.0.0.1:9944`)
- `--keystore-path <KEYSTORE_PATH>`: Node keystore directory (required)
- `--epoch-size <EPOCH_SIZE>`: Number of slots per epoch (optional; default: `1200`)
- `--lang <LANG>`: Language for fixed messages (optional; `ja` | `en`; default: `en`)
- `--tz <TZ>`: Output timezone (optional; default: `UTC`)
  - `UTC` / `local` / `+HH:MM` / `-HH:MM`
  - Unix only: IANA timezones such as `Asia/Tokyo` (sets `TZ` internally and uses system tzdata)
- `--color <auto|always|never>`: Colored output (optional; default: `auto`)
- `--db <DB>`: SQLite DB path (optional; default: `./mblog.db`)
- `--no-store`: Do not write to SQLite (optional; logs only; `--db` path is not required)
- `--ariadne-endpoint <ARIADNE_ENDPOINT>`: Ariadne JSON-RPC endpoint used for sidechain registration checks (optional; default: `https://rpc.testnet-02.midnight.network`)
- `--ariadne-insecure`: Accept invalid TLS certs for Ariadne endpoint (optional)
- `--no-registration-check`: Disable sidechain registration check (optional)
- `--watch`: Continuous monitoring (optional; keeps running without exiting)
- `--output-json`: Output schedule JSON to stdout (optional; cannot be used with `--watch`; exits after printing)
- `--current`: Output the current epoch schedule (requires `--output-json`)
- `--next`: Output the next epoch schedule (requires `--output-json`)

### `mblog log`

- `--db <DB>`: SQLite DB path (optional; default: `./mblog.db`)
- `--epoch <EPOCH>`: Epoch number to display (optional; default: latest)
- `--tz <TZ>`: Scheduled time timezone (optional; default: `UTC`)

See `mblog block --help` and `mblog log --help` for the authoritative list.


### 2) Schedule DB Save, Display Time Zone, Enable Monitoring Mode

```bash
mblog block \
  --keystore-path /path/to/your/keystore \
  --db /path/to/midnight-dir/mblog.db \
  --tz Asia/Tokyo \
  --watch
```

Example results (may vary depending on time zone settings)
```
 Midnight-blocklog - Version: 0.3.1
--------------------------------------------------------------
epoch:245527 (start_slot:294632400 / end_slot:294633599)
      author: 0x52cc8d7dbb573b0fa3ba8e12545affa48313c3e5e0dc0b07515fd52419373360
   ADA Stake: 2816841.654532 ADA (2816841654532 lovelace)
Registration: true (Registered)

Your Block Schedule List
-------------------------
#1 slot 294633422: 2026-01-07T19:42:12+04:00 (UTC 2026-01-07T15:42:12+00:00)
Total=1

Waiting for next session... (next_epoch=245528)
progress [============================= ] 99% (slot 294633599/294633599)
```
>If there is no schedule, it will display `No schedule for this session`.


### 3) JSON schedule output (stdout)

When `--output-json` is set (instead of `--watch`), `mblog` prints the schedule as JSON to stdout (`date` respects `--tz`) and exits.  
Note: `--output-json` does not write to SQLite (it ignores `--db` and does not create/update the DB).

Examples:

```bash
# Current epoch schedule as JSON (date respects --tz)
mblog block --keystore-path /path/to/keystore --tz UTC --output-json --current

# Next epoch schedule as JSON (date respects --tz)
mblog block --keystore-path /path/to/keystore --tz UTC --output-json --next
```

Sample output:

```json
{
  "epoch": 245555,
  "schedule": [
    { "slot": 294663162, "date": "2026-01-10T12:34:56Z" }
  ]
}
```

### 4) Show stored blocks (SQLite)

```bash
# Latest epoch (default)
mblog log --db /path/to/midnight-dir/mblog.db

# Specific epoch
mblog log --db /path/to/midnight-dir/mblog.db --epoch 245525
```

Example results (may vary depending on time zone settings)
```
Midnight Block Log
-------------------

epoch: 245528
|===|==========|==============|===========|===============|===========================|=======================|
| # | status   | block_number | slot      | slot_in_epoch | Scheduled_time            | block_hash            |
|===|==========|==============|===========|===============|===========================|=======================|
| 1 | finality | 3238956      | 294633833 | 233           | 2026-01-07T20:23:18+04:00 | 0xec7a91ac...81f5d053 |
| 2 | finality | 3238966      | 294633843 | 243           | 2026-01-07T20:24:18+04:00 | 0x63ec2189...c0776574 |
|===|==========|==============|===========|===============|===========================|=======================|
```


## What is stored in SQLite
The data stored in SQLite is continuously updated by running this application with `mblog watch`.

On the first run, an SQLite database is created at the `--db` path you specify, and data is accumulated in the following tables. Please note that if you change the path or omit it, a new database will be created.

### Epoch info (`epoch_info`)

- `epoch`: Epoch number
- `start_slot`: Start slot
- `end_slot`: End slot
- `authority_set_hash`: Hash of the Authority set
- `authority_set_len`: Number of elements in the Authority set
- `created_at_utc`: Recorded time (UTC)

### Block info (`blocks`)

- `slot` (primary key)
- `epoch`
- `planned_time_utc`: Planned block production time (UTC)
- `block_number`
- `block_hash`
- `produced_time_utc`
- `status`: `schedule` / `mint` / `finality`

## Security

- This tool does not read or print secret keys (it detects the public key from keystore filenames).
- `author_hasKey` is an RPC that checks whether this node’s keystore contains the corresponding secret key.


## Roadmap
- Indexer Integration
- UX improvements (please open an issue if you have a request)

## License
Apache-2.0

Copyright (c) 2026 BTBF (X-StakePool)

-------


# Midnight-blocklog

Midnightノード向けの **Aura ブロック生成スケジュール表示 + SQLite 記録** ツールです。

※現在このツールはベータ版です。正式リリース前に仕様変更や破壊的変更が行われる可能性があります。

このツールは、ノードの keystore から **Aura 公開鍵を自動検出**し、`author_hasKey` で **このノードが秘密鍵を保持していること**を確認したうえで、現在セッション（ここでは便宜上「epoch」と表記）の担当スロットを計算して記録します。

## できること

- 現在 epoch（session）の **自分の Aura 担当スロット**を計算して表示・SQLite に `schedule` として保存
- 監視モード（`mblog block --watch`）でチェーンを追跡し状態を更新。次のセッションまで待機し境界で新しい epoch の担当スロットを計算・保存します。
  - `schedule`（予定）
  - `mint`（best head で観測）
  - `finality`（finalized で観測）
- epoch ごとに Authority セット情報を保存（ハッシュ/長さ、開始/終了スロットなど）
- 出力タイムゾーン指定、色付き出力（TTY 自動判定）

## 動作要件

- `midnight-node`が以下のフラグで起動していること（WS RPC 有効
  `--rpc-methods=Unsafe`
  `--unsafe-rpc-external`
  `--rpc-port 9944`
- Rust（`cargo`）ビルド環境

## Rust のインストール（rustup）

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable
rustup default stable
rustc -V
cargo -V
```

## ビルド依存（Linux）
Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev
```

## インストール（このリポジトリを clone して `cargo install`）

```bash
git clone https://github.com/btbf/Midnight-blocklog.git
cd Midnight-blocklog
git checkout <latest_tag_name>
cargo install --path . --bin mblog --locked --force
```

`mblog` は通常 `~/.cargo/bin/mblog` にインストールされます。

## 使い方

### 1) ヘルプ表示

```bash
mblog --help
```

出力（実際の `--help`）:

```text
使用方法: mblog <COMMAND>

コマンド:
  block  スロットスケジュール表示（`--watch` で継続監視）
  log    SQLite の blocks 表示
```

## オプション

サブコマンドごとにオプションが異なります。

### `mblog block`

- `--ws <WS>`: WS RPC エンドポイント（省略可能、デフォルト: `ws://127.0.0.1:9944`）
- `--keystore-path <KEYSTORE_PATH>`: ノード keystore ディレクトリ（必須）
- `--epoch-size <EPOCH_SIZE>`: 1 epoch あたりのスロット数（省略可能、デフォルト: `1200`）
- `--lang <LANG>`: 固定メッセージの言語（省略可能、`ja` | `en`、デフォルト: `en`）
- `--tz <TZ>`: 出力タイムゾーン（省略可能、デフォルト: `UTC`）
  - `UTC` / `local` / `+HH:MM` / `-HH:MM`
  - Unix のみ: `Asia/Tokyo` のような IANA タイムゾーン（内部で `TZ` を設定し、システムの tzdata を利用）
- `--color <auto|always|never>`: 色付き出力（省略可能、デフォルト: `auto`）
- `--db <DB>`: SQLite DB パス（省略可能、デフォルト: `./mblog.db`）
- `--no-store`: SQLite に書き込まない（省略可能、ログ表示のみ。`--db` パス不要）
- `--ariadne-endpoint <ARIADNE_ENDPOINT>`: サイドチェーン登録チェックに使用する Ariadne JSON-RPC エンドポイント（省略可能、デフォルト: `https://rpc.testnet-02.midnight.network`）
- `--ariadne-insecure`: Ariadne の TLS 証明書検証をスキップ（自己署名向け; 省略可能）
- `--no-registration-check`: サイドチェーン登録チェックを無効化（省略可能）
- `--watch`: 常時監視（省略可能、終了せずに動作し続ける）
- `--output-json`: スケジュールを JSON で stdout に出力（省略可能、`--watch` と併用不可、出力後に終了）
- `--current`: 現在 epoch のスケジュールを出力（`--output-json` 必須）
- `--next`: 次 epoch のスケジュールを出力（`--output-json` 必須）

### `mblog log`

- `--db <DB>`: SQLite DB パス（省略可能、デフォルト: `./mblog.db`）
- `--epoch <EPOCH>`: 表示する epoch（省略可能、デフォルト: 最新）
- `--tz <TZ>`: Scheduled time の表示タイムゾーン（省略可能、デフォルト: `UTC`）

詳細・最新の一覧は `mblog block --help` と `mblog log --help` を参照してください。


### 2) スケジュールDB保存、表示タイムゾーン、監視モード有効化

```bash
mblog block \
  --keystore-path /path/to/your/keystore \
  --db /path/to/midnight-dir/mblog.db \
  --tz Asia/Tokyo \
  --watch
```

結果の例（タイムゾーン設定により異なります）:
```
 Midnight-blocklog - Version: 0.3.1
--------------------------------------------------------------
epoch:245527 (start_slot:294632400 / end_slot:294633599)
      author: 0x52cc8d7dbb573b0fa3ba8e12545affa48313c3e5e0dc0b07515fd52419373360
   ADA Stake: 2816841.654532 ADA (2816841654532 lovelace)
Registration: true (Registered)

Your Block Schedule List
-------------------------
#1 slot 294633422: 2026-01-07T19:42:12+04:00 (UTC 2026-01-07T15:42:12+00:00)
Total=1

Waiting for next session... (next_epoch=245528)
progress [============================= ] 99% (slot 294633599/294633599)
```
> スケジュールがない場合は `このセッションにスケジュールはありません`と表示されます。


### 3) スケジュールをJSONで出力（stdout）

`--watch` の代わりに `--output-json` を指定すると、スケジュールを JSON で標準出力に出力し（`date` は `--tz` を反映）、出力後に終了します。  
注意: `--output-json` は SQLite には書き込みません（`--db` は無視され、DBの作成/更新も行いません）


```bash
# 現在 epoch のスケジュールを JSON 出力
mblog block --keystore-path /path/to/your/keystore --tz UTC --output-json --current

# 次 epoch のスケジュールを JSON 出力
mblog block --keystore-path /path/to/your/keystore --tz UTC --output-json --next
```

出力例:

```json
{
  "epoch": 245555,
  "schedule": [
    { "slot": 294663162, "date": "2026-01-10T12:34:56Z" }
  ]
}
```

### 4) blocks 表示（SQLite）

```bash
# 最新の epoch（デフォルト）
mblog log --db /path/to/midnight-dir/mblog.db

# epoch 指定
mblog log --db /path/to/midnight-dir/mblog.db --epoch 245525
```

結果の例（タイムゾーン設定により異なります）:
```
Midnight Block Log
-------------------

epoch: 245528
|===|==========|==============|===========|===============|===========================|=======================|
| # | status   | block_number | slot      | slot_in_epoch | Scheduled_time            | block_hash            |
|===|==========|==============|===========|===============|===========================|=======================|
| 1 | finality | 3238956      | 294633833 | 233           | 2026-01-07T20:23:18+04:00 | 0xec7a91ac...81f5d053 |
| 2 | finality | 3238966      | 294633843 | 243           | 2026-01-07T20:24:18+04:00 | 0x63ec2189...c0776574 |
|===|==========|==============|===========|===============|===========================|=======================|
```


## SQLite に保存する内容
SQLiteに格納されるデータは、当アプリケーションを `mblog block --watch` で実行することで継続的に更新されます。

初回起動時に指定した `--db` パスに SQLite データベースが作成され、以下のテーブルにデータを蓄積します。パス変更や省略した場合は新しいdatabaseが作成されるのでご注意ください。

### epoch 情報（`epoch_info`）

- `epoch`: エポック番号
- `start_slot`: 開始スロット
- `end_slot`: 終了スロット
- `authority_set_hash`: Authority セットのハッシュ
- `authority_set_len`: Authority セットの要素数
- `created_at_utc`: 記録時刻（UTC）

### ブロック情報（`blocks`）

- `slot`（主キー）
- `epoch`
- `planned_time_utc`: ブロック生成予定時刻（UTC）
- `block_number`
- `block_hash`
- `produced_time_utc`
- `status`: `schedule` / `mint` / `finality`

## セキュリティ

- このツールは秘密鍵を読み取りません・表示しません（keystore のファイル名から公開鍵を検出します）。
- `author_hasKey` は「このノードの keystore に該当する秘密鍵があるか」を確認する RPC です。


## 今後の予定
- インデクサー連携
- UX改善（リクエストがあればissueを提出してください）

## ライセンス
Apache-2.0

Copyright (c) 2026 BTBF (X-StakePool)

---
