# Midnight-blocklog (English)

A tool for Midnight nodes that **displays the Aura block production schedule and records it in SQLite**.

※This tool is currently in beta. Specifications may change and backward-incompatible changes may occur before the official release.

This tool **auto-detects the Aura public key** from the node keystore, verifies that **this node holds the corresponding secret key** via `author_hasKey`, then calculates and records the assigned slots for the current session (referred to as “epoch” here for convenience).

## What it does

- Calculates your **assigned Aura slots** in the current epoch (session), displays them, and stores them in SQLite as `schedule`
- In watch mode (`--watch`), tracks the chain and updates the status. It waits until the next session, and at the boundary it calculates and stores the assigned slots for the new epoch.
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
Usage: mblog [OPTIONS] --keystore-path <KEYSTORE_PATH>

Options:
      --ws <WS>                        [default: ws://127.0.0.1:9944]
      --keystore-path <KEYSTORE_PATH>  Path to the node's keystore directory. The Aura public key is auto-detected from this
      --epoch-size <EPOCH_SIZE>        [default: 1200]
      --lang <LANG>                    Output language for fixed messages: ja|en [default: en] [possible values: ja, en]
      --tz <TZ>                        Output timezone: "UTC", "local", fixed offset like "+09:00"/"-05:00", or an IANA zone like "Asia/Dubai" (Unix only; uses system tzdata via TZ env) [default: UTC]
      --color <COLOR>                  Colorize output: auto|always|never [default: auto] [possible values: auto, always, never]
      --db <DB>                        SQLite DB path [default: ./mblog.db]
      --no-store                       Do not write to SQLite
      --watch                          Enable continuous monitoring mode (run forever)
  -h, --help                           Print help
  -V, --version                        Print version
```

### 2) Schedule DB Save, Display Time Zone, Enable Monitoring Mode

```bash
mblog \
  --keystore-path /path/to/your/keystore \
  --db /path/to/midnight-dir/mblog.db \
  --tz Asia/Tokyo \
  --watch
```

Example results (may vary depending on time zone settings)
```
 Midnight-blocklog - Version: 0.3.0
--------------------------------------------------------------
epoch:245508 / start_slot:294609600 / end_slot:294610799
author=0x52cc8d7dbb573b0fa3ba8e12545affa48313c3e5e0dc0b07515fd52419373360

Your Block Schedule List
-------------------------
#1 slot 294609854: 2026-01-06T04:25:24+04:00 (UTC 2026-01-06T00:25:24+00:00)
Total=1

Waiting for next session... (next_epoch=245509)
progress [==============                ] 47% (slot 294610168/294610799)
```
>If there is no schedule, it will display `No schedule for this session`.

## Options

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
- `--watch`: Continuous monitoring (optional; keeps running without exiting)

## What is stored in SQLite
The data stored in SQLite is continuously updated by running this application with the `--watch` option.

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
- Display functionality for block production results (per epoch)
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
- 監視モード（`--watch`）でチェーンを追跡し状態を更新。次のセッションまで待機し境界で新しい epoch の担当スロットを計算・保存します。
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
使用方法: mblog [OPTIONS] --keystore-path <KEYSTORE_PATH>

オプション:
      --ws <WS>                        [デフォルト: ws://127.0.0.1:9944]
      --keystore-path <KEYSTORE_PATH>  ノードのkeystoreディレクトリのパス。Aura公開鍵はここから自動検出されます
      --epoch-size <EPOCH_SIZE>        [デフォルト: 1200]
      --lang <LANG>                    固定メッセージの出力言語: ja|en [デフォルト: en] [指定可能な値: ja, en]
      --tz <TZ>                        出力タイムゾーン: "UTC"、"local"、"+09:00"/"-05:00"のような固定オフセット、または"Asia/Dubai"のようなIANAゾーン（Unixのみ; TZ環境変数経由でシステムのtzdataを使用） [デフォルト: UTC]
      --color <COLOR>                  出力のカラー化: auto|always|never [デフォルト: auto] [指定可能な値: auto, always, never]
      --db <DB>                        SQLite DBパス [デフォルト: ./mblog.db]
      --no-store                       SQLiteに書き込まない
      --watch                          継続監視モードを有効化（永続的に実行）
  -h, --help                           ヘルプを表示
  -V, --version                        バージョンを表示
```

### 2) スケジュールDB保存、表示タイムゾーン、監視モード有効化

```bash
mblog \
  --keystore-path /path/to/your/keystore \
  --db /path/to/midnight-dir/mblog.db \
  --tz Asia/Tokyo \
  --watch
```

結果の例（タイムゾーン設定により異なります）:
```
 Midnight-blocklog - Version: 0.3.0
--------------------------------------------------------------
epoch:245508 / start_slot:294609600 / end_slot:294610799
author=0x52cc8d7dbb573b0fa3ba8e12545affa48313c3e5e0dc0b07515fd52419373360

Your Block Schedule List
-------------------------
#1 slot 294609854: 2026-01-06T04:25:24+04:00 (UTC 2026-01-06T00:25:24+00:00)
Total=1

Waiting for next session... (next_epoch=245509)
progress [==============                ] 47% (slot 294610168/294610799)
```
> スケジュールがない場合は `このセッションにスケジュールはありません`と表示されます。


## オプション

- `--ws <WS>`: WS RPC エンドポイント（省略可能、デフォルト: `ws://127.0.0.1:9944`）
- `--keystore-path <KEYSTORE_PATH>`: ノード keystore ディレクトリ（必須）
- `--epoch-size <EPOCH_SIZE>`: 1 epoch あたりのスロット数（省略可能、デフォルト: `1200`）
- `--lang <LANG>`: 固定メッセージの言語（省略可能、`ja` | `en`、デフォルト: `en`）
- `--tz <TZ>`: 出力タイムゾーン（省略可能、デフォルト: `UTC`）
  - `UTC` / `local` / `+HH:MM` / `-HH:MM`
  - Unix のみ: `Asia/Tokyo` のような IANA タイムゾーン（内部で `TZ` を設定し、システムの tzdata を利用）
- `--color <auto|always|never>`: 色付き出力（省略可能、デフォルト: `auto`）
- `--db <DB>`: SQLite DB パス（省略可能、デフォルト: `./mblog.db`）
- `--no-store`: SQLite に書き込まない（省略可能、ログ表示のみ。`--db`パス不要）
- `--watch`: 常時監視（省略可能、終了せずに動作し続ける）

## SQLite に保存する内容
SQLiteに格納されるデータは、当アプリケーションを`--watch`オプション付きで実行することで継続的に更新されます。

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
- ブロック生成実績一覧の表示機能（エポックごと）
- UX改善（リクエストがあればissueを提出してください）

## ライセンス
Apache-2.0

Copyright (c) 2026 BTBF (X-StakePool)

---