use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::io::Write;
use std::{path::Path, time::Duration};
use substrate_api_client::{
	ac_node_api::storage::GetStorageTypes,
	ac_node_api::DecodeAsType,
	ac_primitives::{sr25519, DefaultRuntimeConfig},
	rpc::TungsteniteRpcClient,
	Api, GetChainInfo, GetStorage,
};
use substrate_api_client::rpc::Request;
use anyhow::anyhow;
use chrono::{FixedOffset, Local, Utc};
use rusqlite::{params, params_from_iter, Connection};
use scale_value::{Composite, Primitive, Value as ScaleValue, ValueDef, Variant};
use serde_json::Value;
use sp_core::crypto::{AccountId32, KeyTypeId};
use sp_runtime::generic::DigestItem;
use unicode_width::UnicodeWidthStr;

#[derive(Parser)]
#[command(name = "mblog", version)]
struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Show Aura slot schedule (use --watch to monitor)
	Block(CommonArgs),
	/// Show stored blocks from SQLite
	Log(BlockArgs),
}

#[derive(Args)]
struct CommonArgs {
	    #[arg(long, default_value = "ws://127.0.0.1:9944")]
	    ws: String,
	    /// Path to the node's keystore directory. The Aura public key is auto-detected from this.
	    #[arg(long)]
	    keystore_path: String,
		    #[arg(long, default_value_t = 1200)]
		    epoch_size: u32,
		    /// Output language for fixed messages: ja|en
		    #[arg(long, value_enum, default_value = "en")]
		    lang: Lang,
		    /// Output timezone: "UTC", "local", fixed offset like "+09:00"/"-05:00",
		    /// or an IANA zone like "Asia/Dubai" (Unix only; uses system tzdata via TZ env)
		    #[arg(long, default_value = "UTC")]
		    tz: String,
    /// Colorize output: auto|always|never
    #[arg(long, value_enum, default_value = "auto")]
	    color: ColorMode,
	    /// SQLite DB path
	    #[arg(long, default_value = "./mblog.db")]
	    db: String,
    /// Do not write to SQLite
    #[arg(long)]
    no_store: bool,
	/// Ariadne (testnet) JSON-RPC endpoint used for validator registration checks
	#[arg(long, default_value = "https://rpc.testnet-02.midnight.network")]
	ariadne_endpoint: String,
	/// Accept invalid TLS certs for Ariadne endpoint (for self-signed endpoints)
	#[arg(long)]
	ariadne_insecure: bool,
	/// Disable validator registration check
	#[arg(long)]
	no_registration_check: bool,

	/// Continuously monitor (run forever)
	#[arg(long)]
	watch: bool,

	/// Print metadata / storage availability diagnostics for Session-related items
	#[arg(long, hide = true)]
	debug_metadata: bool,

	/// Print pallet names from runtime metadata (optional filter)
	#[arg(long, hide = true)]
	debug_pallets: bool,

	/// Filter for --debug-pallets (case-insensitive substring)
	#[arg(long, hide = true)]
	debug_pallet_filter: Option<String>,

	/// List storage entry names/types for a pallet: --debug-storage-list <PALLET>
	#[arg(long, hide = true, value_name = "PALLET")]
	debug_storage_list: Option<String>,

	/// Filter for --debug-storage-list (case-insensitive substring)
	#[arg(long, hide = true)]
	debug_storage_filter: Option<String>,

	/// Decode a plain storage item using metadata: --debug-decode-storage <PALLET> <ITEM>
	#[arg(long, hide = true, num_args = 2, value_names = ["PALLET", "ITEM"])]
	debug_decode_storage: Option<Vec<String>>,

	/// Max nesting depth for --debug-decode-storage
	#[arg(long, hide = true, default_value_t = 8)]
	debug_decode_max_depth: usize,

	/// Max items per collection for --debug-decode-storage
	#[arg(long, hide = true, default_value_t = 10)]
	debug_decode_max_items: usize,

	/// Read a plain storage item by name: --debug-storage <PALLET> <ITEM>
	#[arg(long, hide = true, num_args = 2, value_names = ["PALLET", "ITEM"])]
	debug_storage: Option<Vec<String>>,
}

#[derive(Args)]
struct BlockArgs {
	/// SQLite DB path
	#[arg(long, default_value = "./mblog.db")]
	db: String,
	/// Filter by epoch
	#[arg(long)]
	epoch: Option<u64>,
	/// Display timezone for scheduled time (same format as `mblog slot --tz`)
	#[arg(long, default_value = "UTC")]
	tz: String,
	/// Output language for fixed messages: ja|en
	#[arg(long, value_enum, default_value = "en")]
	lang: Lang,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ColorMode {
	Auto,
	Always,
	Never,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Lang {
	Ja,
	En,
}

struct I18n {
	lang: Lang,
}

impl I18n {
	fn new(lang: Lang) -> Self {
		Self { lang }
	}

	fn pick<'a>(&self, en: &'a str, ja: &'a str) -> &'a str {
		match self.lang {
			Lang::En => en,
			Lang::Ja => ja,
		}
	}
}

struct Colors {
	enabled: bool,
}

impl Colors {
	fn new(mode: ColorMode) -> Self {
		let enabled = match mode {
			ColorMode::Always => true,
			ColorMode::Never => false,
			ColorMode::Auto => std::io::stdout().is_terminal(),
		};
		Self { enabled }
	}

	fn wrap(&self, s: impl AsRef<str>, code: &str) -> String {
		let s = s.as_ref();
		if !self.enabled {
			return s.to_string();
		}
		format!("\x1b[{code}m{s}\x1b[0m")
	}

	fn epoch(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "36") // cyan
	}
	fn range(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "33") // yellow
	}
	fn author(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "35") // magenta
	}
	fn slot(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "34") // blue
	}
	fn time(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "32") // green
	}
	fn dim(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "90") // bright black
	}

	fn error(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "31") // red
	}

	fn ok(&self, v: impl AsRef<str>) -> String {
		self.wrap(v, "32") // green
	}
}

fn render_progress_bar(percent: u8, width: usize) -> String {
	let percent = percent.min(100) as usize;
	let filled = (percent * width) / 100;
	let empty = width.saturating_sub(filled);
	format!("[{}{}]", "=".repeat(filled), " ".repeat(empty))
}

fn print_progress(
	is_tty: bool,
	colors: &Colors,
	label: &str,
	percent: u8,
	current_slot: u64,
	end_slot: u64,
) {
	let bar = render_progress_bar(percent, 30);
	let line = format!(
		"{label} {} {}% (slot {}/{})",
		colors.dim(bar),
		colors.epoch(percent.to_string()),
		colors.range(current_slot.to_string()),
		colors.range(end_slot.to_string())
	);

	if is_tty {
		print!("\r\x1b[2K{line}");
		let _ = std::io::stdout().flush();
	} else {
		println!("{line}");
	}
}

enum OutputTz {
	Utc,
	Local,
	/// Local time, but forced via TZ environment (Unix).
	ForcedLocal,
	Fixed(FixedOffset),
}

fn parse_output_tz(s: &str) -> anyhow::Result<OutputTz> {
	let s = s.trim();
	if s.eq_ignore_ascii_case("utc") {
		return Ok(OutputTz::Utc);
	}
	if s.eq_ignore_ascii_case("local") {
		return Ok(OutputTz::Local);
	}
	// Fixed offset: ±HH:MM
	let bytes = s.as_bytes();
	if bytes.len() == 6 && (bytes[0] == b'+' || bytes[0] == b'-') && bytes[3] == b':' {
		let sign = if bytes[0] == b'+' { 1 } else { -1 };
		let hh: i32 = s[1..3].parse()?;
		let mm: i32 = s[4..6].parse()?;
		if hh > 23 || mm > 59 {
			return Err(anyhow!("invalid offset '{s}'"));
		}
		let secs = sign * (hh * 3600 + mm * 60);
		let off = FixedOffset::east_opt(secs).ok_or_else(|| anyhow!("invalid offset '{s}'"))?;
		return Ok(OutputTz::Fixed(off));
	}

	// IANA timezone like "Asia/Dubai"
	if s.contains('/') {
		#[cfg(unix)]
		{
			unsafe {
				std::env::set_var("TZ", s);
				tzset();
			}
			return Ok(OutputTz::ForcedLocal);
		}
		#[cfg(not(unix))]
		{
			return Err(anyhow!(
				"--tz '{s}' looks like an IANA zone, but this mode is only supported on Unix"
			));
		}
	}

	Err(anyhow!(
		"invalid --tz '{s}' (use UTC | local | +HH:MM | -HH:MM | Area/City)"
	))
}

fn format_ts(ts_ms: i64, tz: &OutputTz) -> String {
	let dt_utc = chrono::DateTime::<Utc>::from_timestamp_millis(ts_ms).unwrap_or_else(|| Utc::now());
	format_dt(dt_utc, tz)
}

fn format_dt(dt_utc: chrono::DateTime<chrono::Utc>, tz: &OutputTz) -> String {
	match tz {
		OutputTz::Utc => dt_utc.to_rfc3339(),
		OutputTz::Local => dt_utc.with_timezone(&Local).to_rfc3339(),
		OutputTz::ForcedLocal => dt_utc.with_timezone(&Local).to_rfc3339(),
		OutputTz::Fixed(off) => dt_utc.with_timezone(off).to_rfc3339(),
	}
}

fn parse_rfc3339_utc(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
	let dt = chrono::DateTime::parse_from_rfc3339(s).ok()?;
	Some(dt.with_timezone(&Utc))
}

#[cfg(unix)]
unsafe extern "C" {
	fn tzset();
}

fn hex32(bytes: [u8; 32]) -> String {
	format!("0x{}", hex::encode(bytes))
}

fn ensure_db(conn: &Connection) -> anyhow::Result<()> {
	conn.execute_batch(
		r#"
CREATE TABLE IF NOT EXISTS epoch_info (
  epoch INTEGER PRIMARY KEY,
  start_slot INTEGER NOT NULL,
  end_slot INTEGER NOT NULL,
  authority_set_hash TEXT NOT NULL,
  authority_set_len INTEGER NOT NULL,
  created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
  slot INTEGER PRIMARY KEY,
  epoch INTEGER NOT NULL,
  planned_time_utc TEXT NOT NULL,
  block_number INTEGER,
  block_hash TEXT,
  produced_time_utc TEXT,
  status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocks_epoch ON blocks(epoch);
"#,
	)?;
	Ok(())
}

fn db_upsert_epoch_info(
	conn: &Connection,
	epoch: u64,
	start_slot: u64,
	end_slot: u64,
	authority_set_hash: &str,
	authority_set_len: usize,
) -> anyhow::Result<()> {
	let now_utc = chrono::Utc::now().to_rfc3339();
	conn.execute(
		r#"
INSERT INTO epoch_info(epoch, start_slot, end_slot, authority_set_hash, authority_set_len, created_at_utc)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT(epoch) DO UPDATE SET
  start_slot=excluded.start_slot,
  end_slot=excluded.end_slot,
  authority_set_hash=excluded.authority_set_hash,
  authority_set_len=excluded.authority_set_len,
  created_at_utc=excluded.created_at_utc
"#,
		params![
			epoch as i64,
			start_slot as i64,
			end_slot as i64,
			authority_set_hash,
			authority_set_len as i64,
			now_utc
		],
	)?;
	Ok(())
}

fn db_insert_schedule(
	conn: &mut Connection,
	epoch: u64,
	planned: &[(u64, String)],
) -> anyhow::Result<()> {
	let tx = conn.transaction()?;
	{
		let mut stmt = tx.prepare(
			r#"
INSERT INTO blocks(slot, epoch, planned_time_utc, status)
VALUES (?1, ?2, ?3, 'schedule')
ON CONFLICT(slot) DO UPDATE SET
  epoch=excluded.epoch,
  planned_time_utc=excluded.planned_time_utc,
  status=CASE
    WHEN blocks.status='finality' THEN blocks.status
    ELSE excluded.status
  END
"#,
		)?;
		for (slot, planned_time_utc) in planned {
			stmt.execute(params![*slot as i64, epoch as i64, planned_time_utc])?;
		}
	}
	tx.commit()?;
	Ok(())
}

fn db_update_block_status(
	conn: &Connection,
	slot: u64,
	block_number: u64,
	block_hash: &str,
	produced_time_utc: &str,
	status: &str,
) -> anyhow::Result<()> {
	conn.execute(
		r#"
UPDATE blocks
SET block_number=?2, block_hash=?3, produced_time_utc=?4, status=?5
WHERE slot=?1
  AND (
    (?5='mint' AND status='schedule') OR
    (?5='finality' AND status IN ('schedule','mint'))
  )
"#,
		params![
			slot as i64,
			block_number as i64,
			block_hash,
			produced_time_utc,
			status
		],
	)?;
	Ok(())
}

fn db_upsert_minted_block(
	conn: &Connection,
	slot: u64,
	epoch: u64,
	block_number: u64,
	block_hash: &str,
	produced_time_utc: &str,
) -> anyhow::Result<()> {
	// Unlike finality, mint is rare and only relevant to "our" blocks.
	// If the schedule row is missing for any reason, we still want to record mint.
	conn.execute(
		r#"
INSERT INTO blocks(slot, epoch, planned_time_utc, block_number, block_hash, produced_time_utc, status)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'mint')
ON CONFLICT(slot) DO UPDATE SET
  block_number=excluded.block_number,
  block_hash=excluded.block_hash,
  produced_time_utc=excluded.produced_time_utc,
  status=CASE
    WHEN blocks.status='finality' THEN blocks.status
    WHEN blocks.status='schedule' THEN 'mint'
    ELSE blocks.status
  END
"#,
		params![
			slot as i64,
			epoch as i64,
			produced_time_utc,
			block_number as i64,
			block_hash,
			produced_time_utc
		],
	)?;
	Ok(())
}

#[derive(Clone)]
struct ScheduleRow {
	slot: u64,
	planned_time_utc: String,
	status: String,
	block_number: Option<u64>,
	block_hash: Option<String>,
	produced_time_utc: Option<String>,
}

fn db_fetch_schedule_rows(conn: &Connection, slots: &[u64]) -> anyhow::Result<Vec<ScheduleRow>> {
	if slots.is_empty() {
		return Ok(Vec::new());
	}

	let placeholders = std::iter::repeat("?")
		.take(slots.len())
		.collect::<Vec<_>>()
		.join(",");
	let sql = format!(
		"SELECT slot, planned_time_utc, status, block_number, block_hash, produced_time_utc \
		 FROM blocks WHERE slot IN ({placeholders}) ORDER BY slot ASC"
	);

	let mut stmt = conn.prepare(&sql)?;
	let mut rows = stmt.query(params_from_iter(slots.iter().map(|s| *s as i64)))?;

	let mut out: Vec<ScheduleRow> = Vec::new();
	while let Some(row) = rows.next()? {
		let slot: i64 = row.get(0)?;
		let planned_time_utc: String = row.get(1)?;
		let status: String = row.get(2)?;
		let block_number: Option<i64> = row.get(3)?;
		let block_hash: Option<String> = row.get(4)?;
		let produced_time_utc: Option<String> = row.get(5)?;
		out.push(ScheduleRow {
			slot: slot as u64,
			planned_time_utc,
			status,
			block_number: block_number.map(|n| n as u64),
			block_hash,
			produced_time_utc,
		});
	}
	Ok(out)
}

fn schedule_rows_hash(rows: &[ScheduleRow]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	for r in rows {
		hasher.update(r.slot.to_le_bytes());
		hasher.update(r.planned_time_utc.as_bytes());
		hasher.update(b"\0");
		hasher.update(r.status.as_bytes());
		hasher.update(b"\0");
		if let Some(n) = r.block_number {
			hasher.update(n.to_le_bytes());
		}
		hasher.update(b"\0");
		if let Some(ref h) = r.block_hash {
			hasher.update(h.as_bytes());
		}
		hasher.update(b"\0");
		if let Some(ref t) = r.produced_time_utc {
			hasher.update(t.as_bytes());
		}
		hasher.update(b"\0");
	}
	hasher.finalize().into()
}

fn aura_slot_from_header(
	header: &<DefaultRuntimeConfig as substrate_api_client::ac_primitives::config::Config>::Header,
) -> Option<u64> {
	for log in &header.digest.logs {
		if let DigestItem::PreRuntime(engine_id, data) = log {
			if engine_id != b"aura" {
				continue;
			}
			let raw: [u8; 8] = data.get(0..8)?.try_into().ok()?;
			return Some(u64::from_le_bytes(raw));
		}
	}
	None
}

fn authorities_at(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	at_hash: sp_core::H256,
) -> anyhow::Result<Vec<sr25519::Public>> {
	let res: Option<Vec<sr25519::Public>> = api
		.get_storage("Aura", "Authorities", Some(at_hash))
		.map_err(|e| anyhow!("{e:?}"))?;
	Ok(res.unwrap_or_default())
}

fn scan_new_finalized_blocks(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	conn: Option<&Connection>,
	last_finalized_number: &mut u64,
) -> anyhow::Result<bool> {
	let Some(finalized_hash) = api
		.get_finalized_head()
		.map_err(|e| anyhow!("{e:?}"))?
	else {
		return Ok(false);
	};
	let Some(finalized_header) = api
		.get_header(Some(finalized_hash))
		.map_err(|e| anyhow!("{e:?}"))?
	else {
		return Ok(false);
	};

	let finalized_number: u64 = finalized_header.number.into();
	if finalized_number <= *last_finalized_number {
		return Ok(false);
	}

	// If we don't store anything, just advance the cursor to avoid repeated scans.
	let Some(conn) = conn else {
		*last_finalized_number = finalized_number;
		return Ok(true);
	};

	for n in (*last_finalized_number + 1)..=finalized_number {
		let bn_u32: u32 = n
			.try_into()
			.map_err(|_| anyhow!("finalized block number {n} does not fit u32"))?;
		let Some(h) = api.get_block_hash(Some(bn_u32)).map_err(|e| anyhow!("{e:?}"))? else {
			continue;
		};
		let Some(hdr) = api.get_header(Some(h)).map_err(|e| anyhow!("{e:?}"))? else {
			continue;
		};
		let Some(slot) = aura_slot_from_header(&hdr) else {
			continue;
		};
		let block_hash_str = format!("{h:?}");
		let produced_time_utc = block_time_utc(api, h);
		db_update_block_status(conn, slot, n, &block_hash_str, &produced_time_utc, "finality")?;
	}

	*last_finalized_number = finalized_number;
	Ok(true)
}

fn block_time_utc(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	hash: sp_core::H256,
) -> String {
	let ts_ms: Option<u64> = api
		.get_storage("Timestamp", "Now", Some(hash))
		.map_err(|e| anyhow!("{e:?}"))
		.ok()
		.flatten();
	match ts_ms {
		Some(ms) => chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64)
			.unwrap()
			.to_rfc3339(),
		None => chrono::Utc::now().to_rfc3339(),
	}
}

fn author_has_aura_key(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	public_key_hex: &str,
) -> anyhow::Result<bool> {
	let mut params = substrate_api_client::ac_primitives::RpcParams::new();
	params
		.insert(public_key_hex)
		.map_err(|e| anyhow!("failed to build RPC params: {e}"))?;
	params
		.insert("aura")
		.map_err(|e| anyhow!("failed to build RPC params: {e}"))?;

	api.client()
		.request("author_hasKey", params)
		.map_err(|e| anyhow!("author_hasKey RPC failed: {e:?}"))
}

fn parse_pubkey_hex(s: &str) -> anyhow::Result<[u8; 32]> {
	let hex_str = s.trim_start_matches("0x");
	let bytes = hex::decode(hex_str)?;
	let len = bytes.len();
	let arr: [u8; 32] = bytes
		.as_slice()
		.try_into()
		.map_err(|_| anyhow::anyhow!("expected 32-byte hex, got {} bytes", len))?;
	Ok(arr)
}

fn detect_aura_pubkey_from_keystore(keystore_path: &Path) -> anyhow::Result<String> {
	let mut found: Vec<String> = Vec::new();

	for entry in std::fs::read_dir(keystore_path).map_err(|e| {
		anyhow!("failed to read --keystore-path '{}': {e}", keystore_path.display())
	})? {
		let entry = entry.map_err(|e| anyhow!("failed to read directory entry: {e}"))?;
		let file_type = entry.file_type().map_err(|e| anyhow!("failed to stat entry: {e}"))?;
		if !file_type.is_file() {
			continue;
		}
		let name_os = entry.file_name();
		let Some(name) = name_os.to_str() else {
			continue;
		};
		let mut hex_name = name.trim().to_ascii_lowercase();
		if let Some(rest) = hex_name.strip_prefix("0x") {
			hex_name = rest.to_string();
		}
		// Substrate keystore filenames are typically: <4-byte key type><32-byte pubkey> as hex.
		// For Aura, key type is "aura" => 0x61757261.
		if hex_name.len() == 72 && hex_name.starts_with("61757261") {
			let pub_hex = &hex_name[8..];
			if pub_hex.chars().all(|c| c.is_ascii_hexdigit()) {
				found.push(format!("0x{pub_hex}"));
			}
		}
	}

	found.sort();
	found.dedup();

	match found.len() {
		0 => Err(anyhow!(
			"no Aura key found in keystore '{}': expected a file named like 61757261<pubkey32bytes> (hex)",
			keystore_path.display()
		)),
		1 => Ok(found.remove(0)),
		_ => Err(anyhow!(
			"multiple Aura keys found in keystore '{}': {:?}. Keep only one Aura key, or use a dedicated keystore path.",
			keystore_path.display(),
			found
		)),
	}
}

fn detect_sidechain_pubkey_from_keystore(keystore_path: &Path) -> anyhow::Result<String> {
	let mut found: Vec<String> = Vec::new();

	for entry in std::fs::read_dir(keystore_path).map_err(|e| {
		anyhow!(
			"failed to read --keystore-path '{}' for sidechain key detection: {e}",
			keystore_path.display()
		)
	})? {
		let entry = entry.map_err(|e| anyhow!("failed to read directory entry: {e}"))?;
		let file_type = entry.file_type().map_err(|e| anyhow!("failed to stat entry: {e}"))?;
		if !file_type.is_file() {
			continue;
		}
		let name_os = entry.file_name();
		let Some(name) = name_os.to_str() else {
			continue;
		};
		let mut hex_name = name.trim().to_ascii_lowercase();
		if let Some(rest) = hex_name.strip_prefix("0x") {
			hex_name = rest.to_string();
		}

		// Expect: <4-byte key type><33-byte compressed pubkey> as hex.
		// Many sidechain keys are compressed secp256k1 (33 bytes) starting with 02/03.
		if hex_name.len() != 74 {
			continue;
		}
		let pub_hex = &hex_name[8..];
		if !pub_hex.chars().all(|c| c.is_ascii_hexdigit()) {
			continue;
		}
		if !(pub_hex.starts_with("02") || pub_hex.starts_with("03")) {
			continue;
		}
		found.push(format!("0x{pub_hex}"));
	}

	found.sort();
	found.dedup();

	match found.len() {
		0 => Err(anyhow!(
			"no sidechain public key found in keystore '{}': expected a file named like <keytype><33-byte pubkey> (hex, starts with 02/03)",
			keystore_path.display()
		)),
		1 => Ok(found.remove(0)),
		_ => Err(anyhow!(
			"multiple sidechain public keys found in keystore '{}': {:?}. Keep only one sidechain key, or use a dedicated keystore path.",
			keystore_path.display(),
			found
		)),
	}
}

fn fetch_authorities(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
) -> anyhow::Result<Vec<sr25519::Public>> {
	let res: Option<Vec<sr25519::Public>> = api
		.get_storage("Aura", "Authorities", None)
		.map_err(|e| anyhow!("{e:?}"))?;
	Ok(res.unwrap_or_default())
}

fn format_meta_check(res: Result<(), anyhow::Error>) -> String {
	match res {
		Ok(()) => "ok".to_string(),
		Err(e) => format!("err: {e}"),
	}
}

fn hex_bytes_abbrev(bytes: &[u8], max_hex_chars: usize) -> String {
	let h = hex::encode(bytes);
	if h.len() <= max_hex_chars {
		return format!("0x{h}");
	}
	format!("0x{}...{}", &h[..max_hex_chars], &h[h.len().saturating_sub(32)..])
}

fn status_tag(colors: &Colors, status: &str) -> String {
	match status {
		"finality" => format!(" {}", colors.ok("finality ✅")),
		"mint" => format!(" {}", colors.range("mint🆕")),
		_ => format!(" {}", colors.dim("schedule ⏰")),
	}
}

fn extract_plain_type_id(ty_dbg: &str) -> Option<u32> {
	let pat = "Plain(UntrackedSymbol { id: ";
	let Some(rest) = ty_dbg.strip_prefix(pat) else { return None };
	let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
	n.parse::<u32>().ok()
}

fn print_pallets(api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>, filter: Option<&str>) {
	let filter_lc = filter.map(|s| s.to_lowercase());
	for p in api.metadata().pallets() {
		let name = p.name();
		if let Some(ref f) = filter_lc {
			if !name.to_lowercase().contains(f) {
				continue;
			}
		}
		let storage_len = p.storage().len();
		println!("{name} (index={}, storage={storage_len})", p.index());
	}
}

fn debug_read_plain_storage(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	pallet_name: &str,
	item_name: &str,
) {
	let Some(pallet) = api.metadata().pallet_by_name(pallet_name) else {
		eprintln!("debug-storage: pallet not found: {pallet_name}");
		return;
	};
	let Some(entry) = pallet.storage().find(|e| e.name == item_name) else {
		eprintln!("debug-storage: storage item not found: {pallet_name}.{item_name}");
		return;
	};

	let Ok(val) = entry.get_value(pallet_name) else {
		eprintln!(
			"debug-storage: {pallet_name}.{item_name} is not a plain value storage (ty={:?})",
			entry.ty
		);
		return;
	};

	let ty_dbg = format!("{:?}", entry.ty);
	if let Some(type_id) = extract_plain_type_id(&ty_dbg) {
		let type_path = api
			.metadata()
			.resolve_type(type_id)
			.map(|t| t.path.to_string())
			.filter(|s| !s.is_empty())
			.unwrap_or_else(|| "<unknown>".to_string());
		println!("debug-storage: type=Plain(id={type_id}, path={type_path})");
	}

	let key = val.key();
	println!("debug-storage: key=0x{}", hex::encode(&key.0));
	match api.get_opaque_storage_by_key(key, None) {
		Ok(Some(raw)) => {
			println!(
				"debug-storage: value_bytes={} {}",
				raw.len(),
				hex_bytes_abbrev(&raw, 256)
			);
		}
		Ok(None) => println!("debug-storage: value=null"),
		Err(e) => eprintln!("debug-storage: read error: {e:?}"),
	}
}

fn summarize_primitive(p: &Primitive) -> String {
	match p {
		Primitive::Bool(b) => b.to_string(),
		Primitive::Char(c) => c.to_string(),
		Primitive::String(s) => {
			if s.len() <= 120 {
				format!("{s:?}")
			} else {
				format!("{:?}...", &s[..120])
			}
		}
		Primitive::U128(n) => n.to_string(),
		Primitive::I128(n) => n.to_string(),
		Primitive::U256(b) | Primitive::I256(b) => format!("0x{}", hex::encode(b)),
	}
}

fn value_as_u64(v: &ScaleValue<()>) -> Option<u64> {
	match &v.value {
		ValueDef::Primitive(Primitive::U128(n)) => (*n).try_into().ok(),
		_ => None,
	}
}

fn value_as_unnamed(v: &ScaleValue<()>) -> Option<&[ScaleValue<()>]> {
	match &v.value {
		ValueDef::Composite(Composite::Unnamed(values)) => Some(values),
		_ => None,
	}
}

fn value_as_named(v: &ScaleValue<()>) -> Option<&[(String, ScaleValue<()>)]> {
	match &v.value {
		ValueDef::Composite(Composite::Named(values)) => Some(values),
		_ => None,
	}
}

fn value_as_bytes(v: &ScaleValue<()>) -> Option<Vec<u8>> {
	let items = value_as_unnamed(v)?;
	let mut out = Vec::with_capacity(items.len());
	for it in items {
		let Some(b) = value_as_u64(it) else { return None };
		let b: u8 = b.try_into().ok()?;
		out.push(b);
	}
	Some(out)
}

fn value_as_wrapped_bytes(v: &ScaleValue<()>) -> Option<Vec<u8>> {
	// Many values appear as Composite::Unnamed(len=1) -> Composite::Unnamed(len=N) -> [u8...]
	let items = value_as_unnamed(v)?;
	if items.len() != 1 {
		return None;
	}
	value_as_bytes(&items[0])
}

fn value_as_wrapped_u64(v: &ScaleValue<()>) -> Option<u64> {
	let items = value_as_unnamed(v)?;
	if items.len() != 1 {
		return None;
	}
	value_as_u64(&items[0])
}

fn hex0x(bytes: &[u8]) -> String {
	format!("0x{}", hex::encode(bytes))
}

fn debug_pretty_committee_info(v: &ScaleValue<()>, max_items: usize) -> Option<Vec<String>> {
	// Expected shape:
	// Composite::Named { epoch: (u64), committee: [slot -> (sidechain_pub_key(33), {aura(32), grandpa(32)})] }
	let named = value_as_named(v)?;
	let epoch_v = named.iter().find(|(k, _)| k == "epoch")?.1.clone();
	let committee_v = named.iter().find(|(k, _)| k == "committee")?.1.clone();

	let epoch = value_as_wrapped_u64(&epoch_v)?;
	let committee_outer = value_as_unnamed(&committee_v)?;
	if committee_outer.len() != 1 {
		return None;
	}
	let schedule = value_as_unnamed(&committee_outer[0])?;

	let mut out = Vec::new();
	out.push(format!("CommitteeInfo(epoch={epoch}, slots={})", schedule.len()));

	let mut shown = 0usize;
	for (idx, entry) in schedule.iter().enumerate() {
		if shown >= max_items {
			break;
		}
		let parts = value_as_unnamed(entry)?;
		if parts.len() != 2 {
			continue;
		}
		let sidechain = value_as_wrapped_bytes(&parts[0])?;
		let keys_named = value_as_named(&parts[1])?;
		let aura_v = keys_named.iter().find(|(k, _)| k == "aura")?.1.clone();
		let grandpa_v = keys_named.iter().find(|(k, _)| k == "grandpa")?.1.clone();
		let aura = value_as_wrapped_bytes(&aura_v)?;
		let grandpa = value_as_wrapped_bytes(&grandpa_v)?;

		out.push(format!(
			"  slot[{idx}]: sidechain={} aura={} grandpa={}",
			hex0x(&sidechain),
			hex0x(&aura),
			hex0x(&grandpa)
		));
		shown += 1;
	}

	if schedule.len() > shown {
		out.push(format!("  ... ({} more)", schedule.len().saturating_sub(shown)));
	}
	Some(out)
}

fn fetch_committee_info(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	pallet_name: &str,
	item_name: &str,
) -> anyhow::Result<Option<(u64, Vec<([u8; 32], [u8; 32])>)>> {
	let Some(pallet) = api.metadata().pallet_by_name(pallet_name) else {
		return Ok(None);
	};
	let Some(entry) = pallet.storage().find(|e| e.name == item_name) else {
		return Ok(None);
	};
	let ty_dbg = format!("{:?}", entry.ty);
	let Some(type_id) = extract_plain_type_id(&ty_dbg) else {
		return Ok(None);
	};
	let Ok(val) = entry.get_value(pallet_name) else {
		return Ok(None);
	};
	let key = val.key();
	let raw = match api.get_opaque_storage_by_key(key, None) {
		Ok(Some(b)) => b,
		Ok(None) => return Ok(None),
		Err(e) => return Err(anyhow!("{e:?}")),
	};
	let v = ScaleValue::<()>::decode_as_type(&mut raw.as_slice(), type_id, api.metadata().types())
		.map_err(|e| anyhow!("{e}"))?;

	let named = value_as_named(&v).ok_or_else(|| anyhow!("CommitteeInfo decode: expected named composite"))?;
	let epoch_v = named
		.iter()
		.find(|(k, _)| k == "epoch")
		.ok_or_else(|| anyhow!("CommitteeInfo decode: missing epoch"))?
		.1
		.clone();
	let committee_v = named
		.iter()
		.find(|(k, _)| k == "committee")
		.ok_or_else(|| anyhow!("CommitteeInfo decode: missing committee"))?
		.1
		.clone();

	let epoch = value_as_wrapped_u64(&epoch_v).ok_or_else(|| anyhow!("CommitteeInfo decode: epoch"))?;

	let committee_outer = value_as_unnamed(&committee_v).ok_or_else(|| anyhow!("CommitteeInfo decode: committee outer"))?;
	if committee_outer.len() != 1 {
		return Err(anyhow!(
			"CommitteeInfo decode: expected committee outer len=1, got {}",
			committee_outer.len()
		));
	}
	let schedule = value_as_unnamed(&committee_outer[0]).ok_or_else(|| anyhow!("CommitteeInfo decode: schedule"))?;

	let mut out: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(schedule.len());
	for entry in schedule {
		let parts = value_as_unnamed(entry).ok_or_else(|| anyhow!("CommitteeInfo decode: entry parts"))?;
		if parts.len() != 2 {
			return Err(anyhow!("CommitteeInfo decode: expected entry len=2, got {}", parts.len()));
		}
		let keys_named =
			value_as_named(&parts[1]).ok_or_else(|| anyhow!("CommitteeInfo decode: keys named"))?;
		let aura_v = keys_named
			.iter()
			.find(|(k, _)| k == "aura")
			.ok_or_else(|| anyhow!("CommitteeInfo decode: missing aura"))?
			.1
			.clone();
		let grandpa_v = keys_named
			.iter()
			.find(|(k, _)| k == "grandpa")
			.ok_or_else(|| anyhow!("CommitteeInfo decode: missing grandpa"))?
			.1
			.clone();
		let aura_bytes =
			value_as_wrapped_bytes(&aura_v).ok_or_else(|| anyhow!("CommitteeInfo decode: aura bytes"))?;
		let grandpa_bytes = value_as_wrapped_bytes(&grandpa_v)
			.ok_or_else(|| anyhow!("CommitteeInfo decode: grandpa bytes"))?;
		let aura_len = aura_bytes.len();
		let aura_arr: [u8; 32] = aura_bytes
			.try_into()
			.map_err(|_| anyhow!("CommitteeInfo decode: aura len={aura_len}"))?;
		let grandpa_len = grandpa_bytes.len();
		let grandpa_arr: [u8; 32] = grandpa_bytes
			.try_into()
			.map_err(|_| anyhow!("CommitteeInfo decode: grandpa len={grandpa_len}"))?;
		out.push((aura_arr, grandpa_arr));
	}

	Ok(Some((epoch, out)))
}

fn print_next_committee_for_author(
	i18n: &I18n,
	colors: &Colors,
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	author_bytes: &[u8; 32],
	latest_slot: u64,
	ts_ms: u64,
	slot_dur_ms: u64,
	next_start_slot: u64,
	out_tz: &OutputTz,
	utc_tz: &OutputTz,
) {
	let res = fetch_committee_info(api, "SessionCommitteeManagement", "NextCommittee");
	let (next_epoch, schedule) = match res {
		Ok(Some(v)) => v,
		Ok(None) => {
			println!(
				"{}",
				colors.dim(i18n.pick(
					"Next committee is not available on this runtime.",
					"次エポックの委員会情報はこのランタイムでは取得できません。",
				))
			);
			return;
		}
		Err(e) => {
			println!(
				"{}: {}",
				colors.dim(i18n.pick(
					"Next committee read failed",
					"次エポックの委員会情報の取得に失敗しました",
				)),
				colors.dim(e.to_string())
			);
			return;
		}
	};

	let mut my: Vec<u64> = Vec::new();
	for (i, (aura, _grandpa)) in schedule.iter().enumerate() {
		if aura == author_bytes {
			my.push(next_start_slot + (i as u64));
		}
	}

	println!(
		"{}: {}",
		i18n.pick("Next epoch schedule", "次のエポックスケジュール"),
		colors.epoch(next_epoch.to_string())
	);
	println!("-------------------------");

	if my.is_empty() {
		println!("{}", colors.dim(i18n.pick("No assignment in next epoch.", "次エポックの割当はありません。")));
		return;
	}

	for (idx, slot) in my.iter().enumerate() {
		let delta_slots = *slot as i64 - latest_slot as i64;
		let ts = ts_ms as i64 + (delta_slots * slot_dur_ms as i64);
		let out_ts = colors.time(format_ts(ts, out_tz));
		let utc_ts = format_ts(ts, utc_tz);
		println!(
			"#{} slot {}: {} (UTC {})",
			idx + 1,
			colors.slot(slot.to_string()),
			out_ts,
			colors.dim(utc_ts)
		);
	}
	println!("{}={}", i18n.pick("Total", "合計"), my.len());
}

fn summarize_value_lines(
	v: &ScaleValue<()>,
	depth: usize,
	indent: usize,
	max_depth: usize,
	max_items: usize,
) -> Vec<String> {
	let pad = " ".repeat(indent);
	match &v.value {
		ValueDef::Primitive(p) => vec![format!("{pad}{}", summarize_primitive(p))],
		ValueDef::BitSequence(bits) => vec![format!("{pad}bits(len={})", bits.len())],
		ValueDef::Variant(Variant { name, values }) => {
			let mut out = vec![format!("{pad}Variant({name})")];
			if depth >= max_depth {
				out.push(format!("{pad}  ..."));
				return out;
			}
			out.extend(summarize_composite_lines(
				values,
				depth + 1,
				indent + 2,
				max_depth,
				max_items,
			));
			out
		}
		ValueDef::Composite(c) => summarize_composite_lines(c, depth, indent, max_depth, max_items),
	}
}

fn summarize_composite_lines(
	c: &Composite<()>,
	depth: usize,
	indent: usize,
	max_depth: usize,
	max_items: usize,
) -> Vec<String> {
	let pad = " ".repeat(indent);
	match c {
		Composite::Named(fields) => {
			let mut out = vec![format!("{pad}Composite::Named(len={})", fields.len())];
			if depth >= max_depth {
				out.push(format!("{pad}  ..."));
				return out;
			}
			for (idx, (k, v)) in fields.iter().enumerate() {
				if idx >= max_items {
					out.push(format!("{pad}  ... ({} more)", fields.len().saturating_sub(max_items)));
					break;
				}
				let mut lines = summarize_value_lines(v, depth + 1, indent + 4, max_depth, max_items);
				if let Some(first) = lines.first_mut() {
					*first = format!("{pad}  {k}: {}", first.trim_start());
				}
				out.extend(lines);
			}
			out
		}
		Composite::Unnamed(values) => {
			let mut out = vec![format!("{pad}Composite::Unnamed(len={})", values.len())];
			if depth >= max_depth {
				out.push(format!("{pad}  ..."));
				return out;
			}
			for (idx, v) in values.iter().enumerate() {
				if idx >= max_items {
					out.push(format!("{pad}  ... ({} more)", values.len().saturating_sub(max_items)));
					break;
				}
				let mut lines = summarize_value_lines(v, depth + 1, indent + 4, max_depth, max_items);
				if let Some(first) = lines.first_mut() {
					*first = format!("{pad}  [{idx}]: {}", first.trim_start());
				}
				out.extend(lines);
			}
			out
		}
	}
}

fn debug_decode_plain_storage(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	pallet_name: &str,
	item_name: &str,
	max_depth: usize,
	max_items: usize,
) {
	let Some(pallet) = api.metadata().pallet_by_name(pallet_name) else {
		eprintln!("debug-decode-storage: pallet not found: {pallet_name}");
		return;
	};
	let Some(entry) = pallet.storage().find(|e| e.name == item_name) else {
		eprintln!("debug-decode-storage: storage item not found: {pallet_name}.{item_name}");
		return;
	};
	let ty_dbg = format!("{:?}", entry.ty);
	let Some(type_id) = extract_plain_type_id(&ty_dbg) else {
		eprintln!("debug-decode-storage: storage is not Plain: {ty_dbg}");
		return;
	};
	let type_path = api
		.metadata()
		.resolve_type(type_id)
		.map(|t| t.path.to_string())
		.filter(|s| !s.is_empty())
		.unwrap_or_else(|| "<unknown>".to_string());

	let Ok(val) = entry.get_value(pallet_name) else {
		eprintln!("debug-decode-storage: {pallet_name}.{item_name} is not a plain value storage");
		return;
	};
	let key = val.key();
	let raw = match api.get_opaque_storage_by_key(key, None) {
		Ok(Some(b)) => b,
		Ok(None) => {
			println!("debug-decode-storage: value=null");
			return;
		}
		Err(e) => {
			eprintln!("debug-decode-storage: read error: {e:?}");
			return;
		}
	};

	println!("debug-decode-storage: type=Plain(id={type_id}, path={type_path})");
	match ScaleValue::<()>::decode_as_type(&mut raw.as_slice(), type_id, api.metadata().types()) {
		Ok(v) => {
			println!("debug-decode-storage: decoded (summary)");
			if type_path == "pallet_session_validator_management::pallet::CommitteeInfo" {
				if let Some(lines) = debug_pretty_committee_info(&v, max_items) {
					for line in lines {
						println!("{line}");
					}
					return;
				}
			}
			for line in summarize_value_lines(&v, 0, 0, max_depth, max_items) {
				println!("{line}");
			}
		}
		Err(e) => {
			eprintln!("debug-decode-storage: decode error: {e}");
		}
	}
}

fn debug_list_storage(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	pallet_name: &str,
	filter: Option<&str>,
) {
	let Some(pallet) = api.metadata().pallet_by_name(pallet_name) else {
		eprintln!("debug-storage-list: pallet not found: {pallet_name}");
		return;
	};

	let filter_lc = filter.map(|s| s.to_lowercase());
	println!("{pallet_name} storage entries");
	println!("---------------------");
	for entry in pallet.storage() {
		let name = entry.name.as_str();
		if let Some(ref f) = filter_lc {
			if !name.to_lowercase().contains(f) {
				continue;
			}
		}
		let ty_dbg = format!("{:?}", entry.ty);
		if let Some(type_id) = extract_plain_type_id(&ty_dbg) {
			let type_path = api
				.metadata()
				.resolve_type(type_id)
				.map(|t| t.path.to_string())
				.filter(|s| !s.is_empty())
				.unwrap_or_else(|| "<unknown>".to_string());
			println!("{name}: Plain(id={type_id}, path={type_path})");
		} else {
			println!("{name}: {ty_dbg}");
		}
	}
}

fn debug_session_metadata(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
	author_bytes: &[u8; 32],
) -> Vec<(String, String)> {
	let mut rows = Vec::new();

	rows.push((
		"meta Session pallet".to_string(),
		if api.metadata().pallet_by_name("Session").is_some() {
			"present".to_string()
		} else {
			"missing".to_string()
		},
	));

	let check = |pallet: &'static str, item: &'static str| -> Result<(), anyhow::Error> {
		api.metadata()
			.storage_value_key(pallet, item)
			.map(|_| ())
			.map_err(|e| anyhow!("{e:?}"))
	};
	let check_map = |pallet: &'static str, item: &'static str| -> Result<(), anyhow::Error> {
		api.metadata()
			.storage_map_key_prefix(pallet, item)
			.map(|_| ())
			.map_err(|e| anyhow!("{e:?}"))
	};
	let check_double_prefix =
		|pallet: &'static str, item: &'static str, first: KeyTypeId| -> Result<(), anyhow::Error> {
			api.metadata()
				.storage_double_map_key_prefix(pallet, item, first)
				.map(|_| ())
				.map_err(|e| anyhow!("{e:?}"))
		};

	rows.push((
		"meta Session.Validators".to_string(),
		format_meta_check(check("Session", "Validators")),
	));
	rows.push((
		"meta Session.QueuedValidators".to_string(),
		format_meta_check(check("Session", "QueuedValidators")),
	));
	rows.push((
		"meta Session.QueuedKeys".to_string(),
		format_meta_check(check("Session", "QueuedKeys")),
	));
	rows.push((
		"meta Session.NextKeys(map)".to_string(),
		format_meta_check(check_map("Session", "NextKeys")),
	));
	rows.push((
		"meta Session.KeyOwner(dbl)".to_string(),
		format_meta_check(check_double_prefix("Session", "KeyOwner", KeyTypeId(*b"aura"))),
	));

	// State checks (do not swallow errors)
	match api.get_storage::<Vec<AccountId32>>("Session", "Validators", None) {
		Ok(Some(vs)) => rows.push(("state Session.Validators".to_string(), format!("len={}", vs.len()))),
		Ok(None) => rows.push(("state Session.Validators".to_string(), "null".to_string())),
		Err(e) => rows.push(("state Session.Validators".to_string(), format!("err: {e:?}"))),
	}
	match api.get_storage::<Vec<AccountId32>>("Session", "QueuedValidators", None) {
		Ok(Some(vs)) => rows.push((
			"state Session.QueuedValidators".to_string(),
			format!("len={}", vs.len()),
		)),
		Ok(None) => rows.push(("state Session.QueuedValidators".to_string(), "null".to_string())),
		Err(e) => rows.push(("state Session.QueuedValidators".to_string(), format!("err: {e:?}"))),
	}

	let key_type = KeyTypeId(*b"aura");
	let pubkey = author_bytes.to_vec();
	match api.get_storage_double_map::<KeyTypeId, Vec<u8>, AccountId32>("Session", "KeyOwner", key_type, pubkey, None)
	{
		Ok(Some(a)) => rows.push(("state Session.KeyOwner(aura)".to_string(), hex_account_id32(&a))),
		Ok(None) => rows.push(("state Session.KeyOwner(aura)".to_string(), "null".to_string())),
		Err(e) => rows.push(("state Session.KeyOwner(aura)".to_string(), format!("err: {e:?}"))),
	}

	rows
}

fn account_id32_bytes(a: &AccountId32) -> &[u8] {
	<AccountId32 as AsRef<[u8]>>::as_ref(a)
}

fn hex_account_id32(a: &AccountId32) -> String {
	format!("0x{}", hex::encode(account_id32_bytes(a)))
}

fn hash_authorities(auths: &[sr25519::Public]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	for a in auths {
		let bytes: &[u8] = a.as_ref();
		hasher.update(bytes);
	}
	hasher.finalize().into()
}

fn author_in_authorities(author_bytes: &[u8; 32], auths: &[sr25519::Public]) -> bool {
	auths.iter().any(|a| {
		let bytes: &[u8] = a.as_ref();
		bytes == author_bytes.as_slice()
	})
}

fn schedule_hash(slots: &[u64]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	for s in slots {
		hasher.update(s.to_le_bytes());
	}
	hasher.finalize().into()
}

fn compute_my_slots(
	auths: &[sr25519::Public],
	author_bytes: &[u8; 32],
	start_slot: u64,
	slots_to_scan: u64,
) -> Vec<u64> {
	let mut out = Vec::new();
	if auths.is_empty() {
		return out;
	}
	for i in 0..slots_to_scan {
		let slot = start_slot + i;
		let who = &auths[(slot as usize) % auths.len()];
		let who_bytes: &[u8] = who.as_ref();
		if who_bytes == author_bytes.as_slice() {
			out.push(slot);
		}
	}
	out
}

fn print_kv_table(rows: &[(String, String)]) {
	let max_w = rows
		.iter()
		.map(|(k, _)| UnicodeWidthStr::width(k.as_str()))
		.max()
		.unwrap_or(0);
	for (k, v) in rows {
		let w = UnicodeWidthStr::width(k.as_str());
		let pad = max_w.saturating_sub(w);
		println!("{}{}: {}", " ".repeat(pad), k, v);
	}
}

fn format_rfc3339_in_tz(s: &str, out_tz: &OutputTz) -> String {
	let s = s.trim();
	if s.is_empty() || s == "-" {
		return "-".to_string();
	}
	let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) else {
		return s.to_string();
	};
	let dt_utc = dt.with_timezone(&Utc);
	match out_tz {
		OutputTz::Utc => dt_utc.to_rfc3339(),
		OutputTz::Local | OutputTz::ForcedLocal => dt_utc.with_timezone(&Local).to_rfc3339(),
		OutputTz::Fixed(off) => dt_utc.with_timezone(off).to_rfc3339(),
	}
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
	let mut widths: Vec<usize> = headers.iter().map(|h| UnicodeWidthStr::width(*h)).collect();
	for row in rows {
		for (i, cell) in row.iter().enumerate() {
			let w = UnicodeWidthStr::width(cell.as_str());
			if w > widths[i] {
				widths[i] = w;
			}
		}
	}

	let border = {
		let mut s = String::new();
		s.push('|');
		for w in &widths {
			s.push_str(&"=".repeat(*w + 2));
			s.push('|');
		}
		s
	};

	println!("{border}");
	println!(
		"|{}|",
		headers
			.iter()
			.enumerate()
			.map(|(i, h)| format!(" {:<width$} ", *h, width = widths[i]))
			.collect::<Vec<_>>()
			.join("|")
	);
	println!("{border}");
	for row in rows {
		println!(
			"|{}|",
			row.iter()
				.enumerate()
				.map(|(i, c)| format!(" {:<width$} ", c, width = widths[i]))
				.collect::<Vec<_>>()
				.join("|")
		);
	}
	println!("{border}");
}

fn run_block(args: BlockArgs) -> anyhow::Result<()> {
	let conn = Connection::open(&args.db)?;
	let out_tz = parse_output_tz(&args.tz)?;
	let i18n = I18n::new(args.lang);
	let epoch = match args.epoch {
		Some(e) => e,
		None => conn
			.query_row("SELECT MAX(epoch) FROM epoch_info", [], |r| r.get::<_, Option<i64>>(0))
			.or_else(|_| conn.query_row("SELECT MAX(epoch) FROM blocks", [], |r| r.get::<_, Option<i64>>(0)))?
			.map(|v| v as u64)
			.ok_or_else(|| anyhow!("no epoch found in DB (epoch_info/blocks empty)"))?,
	};
	let mut stmt = conn.prepare(
		"SELECT b.slot, b.status, b.block_number, b.block_hash, b.planned_time_utc, e.start_slot \
		 FROM blocks b LEFT JOIN epoch_info e ON b.epoch = e.epoch \
		 WHERE b.epoch = ?1 ORDER BY b.slot ASC",
	)?;

	let mut rows_out: Vec<Vec<String>> = Vec::new();
	let mut idx: u64 = 0;
	let mut start_slot: Option<u64> = None;

	let mut rows = stmt.query([epoch as i64])?;
	while let Some(row) = rows.next()? {
		idx += 1;
		let slot: u64 = row.get::<_, i64>(0)? as u64;
		let status: String = row.get(1)?;
		let block_number: Option<i64> = row.get(2)?;
		let block_hash: Option<String> = row.get(3)?;
		let planned: Option<String> = row.get(4)?;
		let st: Option<i64> = row.get(5)?;
		if start_slot.is_none() {
			start_slot = st.map(|v| v as u64);
		}

		let slot_in_epoch = start_slot.map(|s| slot.saturating_sub(s));
		let bn = block_number.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string());
		let hash = block_hash.unwrap_or_else(|| "-".to_string());
		let scheduled = planned
			.as_deref()
			.map(|s| format_rfc3339_in_tz(s, &out_tz))
			.unwrap_or_else(|| "-".to_string());

		rows_out.push(vec![
			idx.to_string(),
			status,
			bn,
			slot.to_string(),
			slot_in_epoch.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
			scheduled,
			hash,
		]);
	}

	println!("Midnight Block Log");
	println!("-------------------");
	println!();
	println!("epoch: {}", epoch);
	if rows_out.is_empty() {
		let msg = i18n.pick(
			"No block production logs for this epoch.",
			"このエポックにはブロック生成ログがありません",
		);
		eprintln!();
		if std::io::stdout().is_terminal() {
			eprintln!("\x1b[31m{msg}\x1b[0m");
		} else {
			eprintln!("{msg}");
		}
		eprintln!();
		return Ok(());
	}
	print_table(
		&[
			"#",
			"status",
			"block_number",
			"slot",
			"slot_in_epoch",
			"Scheduled_time",
			"block_hash",
		],
		&rows_out,
	);
	println!();
	Ok(())
}

fn jsonrpc_http_call(
	client: &reqwest::blocking::Client,
	endpoint: &str,
	method: &str,
	params: Value,
) -> anyhow::Result<Value> {
	let request_body = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": method,
		"params": params,
	});
	let res: Value = client
		.post(endpoint)
		.json(&request_body)
		.send()?
		.error_for_status()?
		.json()?;
	if let Some(err) = res.get("error") {
		return Err(anyhow!("JSON-RPC error: {}", serde_json::to_string(err)?));
	}
	Ok(res
		.get("result")
		.cloned()
		.unwrap_or(Value::Null))
}

fn parse_lovelace(v: &Value) -> Option<u128> {
	match v {
		Value::Number(n) => n.as_u64().map(|u| u as u128),
		Value::String(s) => s.parse::<u128>().ok(),
		_ => None,
	}
}

fn format_ada_from_lovelace(lovelace: u128) -> String {
	const UNIT: u128 = 1_000_000;
	let whole = lovelace / UNIT;
	let frac = (lovelace % UNIT) as u64;
	if frac == 0 {
		return whole.to_string();
	}
	let mut frac_s = format!("{frac:06}");
	while frac_s.ends_with('0') {
		frac_s.pop();
	}
	format!("{whole}.{frac_s}")
}

fn fetch_registration_status(
	client: &reqwest::blocking::Client,
	endpoint: &str,
	sidechain_pubkey: &str,
	mainchain_epoch: u64,
) -> anyhow::Result<(u128, bool)> {
	let ariadne = jsonrpc_http_call(
		client,
		endpoint,
		"sidechain_getAriadneParameters",
		Value::Array(vec![Value::Number(mainchain_epoch.into())]),
	)?;

	let Some(regs) = ariadne
		.get("candidateRegistrations")
		.and_then(|v| v.as_object())
	else {
		return Ok((0, false));
	};

	for (_mainchain_pubkey, entries) in regs {
		let Some(arr) = entries.as_array() else { continue };
		for entry in arr {
			let sc = entry.get("sidechainPubKey").and_then(|v| v.as_str());
			if sc != Some(sidechain_pubkey) {
				continue;
			}
			let stake = entry
				.get("stakeDelegation")
				.and_then(parse_lovelace)
				.unwrap_or(0);
			let is_valid = entry.get("isValid").and_then(|v| v.as_bool()).unwrap_or(false);
			return Ok((stake, is_valid));
		}
	}
	Ok((0, false))
}

fn run(common: CommonArgs) -> anyhow::Result<()> {
	let i18n = I18n::new(common.lang);
	let colors = Colors::new(common.color);
	let is_tty = std::io::stdout().is_terminal();
	let live_update = common.watch && is_tty;
	let banner = format!(
		"\n Midnight-blocklog - {}: {}\n--------------------------------------------------------------\n",
		i18n.pick("Version", "バージョン"),
		env!("CARGO_PKG_VERSION")
	);
	print!("{banner}");
				let mut conn = if common.no_store {
					None
				} else {
				let conn = Connection::open(&common.db)?;
				ensure_db(&conn)?;
				Some(conn)
			};
	let author_hex =
		detect_aura_pubkey_from_keystore(Path::new(&common.keystore_path))?;
	let author_bytes =
		parse_pubkey_hex(&author_hex).map_err(|e| anyhow!("invalid aura pubkey from keystore: {e}"))?;
	let sidechain_pubkey = if common.no_registration_check {
		None
	} else {
		Some(detect_sidechain_pubkey_from_keystore(Path::new(&common.keystore_path))?)
	};
	let ariadne_client = if common.no_registration_check {
		None
	} else {
		Some(
			reqwest::blocking::Client::builder()
				.user_agent(format!("mblog/{}", env!("CARGO_PKG_VERSION")))
				.danger_accept_invalid_certs(common.ariadne_insecure)
				.build()?,
		)
	};
	let out_tz = parse_output_tz(&common.tz)?;
	let utc_tz = OutputTz::Utc;

    let client = TungsteniteRpcClient::new(&common.ws, 3)
		.map_err(|e| anyhow!("rpc client init failed: {e:?}"))?;
    let api: Api<DefaultRuntimeConfig, TungsteniteRpcClient> =
		Api::new(client).map_err(|e| anyhow!("api init failed: {e:?}"))?;

	let has = author_has_aura_key(&api, &author_hex)?;
	if !has {
		return Err(anyhow!(
			"Refusing to run: detected Aura key {} is not present in this node's keystore (author_hasKey=false).",
			author_hex
		));
	}

	let epoch_size = common.epoch_size as u64;

	let mut prev_hash: Option<[u8; 32]> = None;
	let mut prev_len: usize = 0;
	let mut prev_author_present: Option<bool> = None;
	let mut prev_my_schedule_hash: Option<[u8; 32]> = None;
	let mut prev_schedule_view_hash: Option<[u8; 32]> = None;
	let mut prev_epoch: Option<u64> = None;
	let mut cached_epoch_rows: Option<Vec<(String, String)>> = None;
	let mut current_my_slots: Vec<u64> = Vec::new();
	let mut pending_next_committee_print: bool = true; // also print on first render
	let mut next_preview_printed: bool = false;
	let mut waiting_notice_printed: bool = false;
	let mut waiting_progress_tick: u64 = 0;
	// Do not backfill from genesis on startup; initialize cursors from the current chain state.
	let initial_best_hash: Option<sp_core::H256> = api
		.get_block_hash(None)
		.map_err(|e| anyhow!("{e:?}"))?;
	let mut last_best_number: u64 = match initial_best_hash {
		Some(h) => api
			.get_header(Some(h))
			.map_err(|e| anyhow!("{e:?}"))?
			.map(|hdr| hdr.number.into())
			.unwrap_or(0),
		None => 0,
	};
	let mut last_finalized_number: u64 = match api
		.get_finalized_head()
		.map_err(|e| anyhow!("{e:?}"))?
	{
		Some(h) => api
			.get_header(Some(h))
			.map_err(|e| anyhow!("{e:?}"))?
			.map(|hdr| hdr.number.into())
			.unwrap_or(0),
		None => 0,
	};

	if common.debug_metadata {
		println!();
		println!("Session metadata / state diagnostics");
		println!("----------------------------------");
		let rows = debug_session_metadata(&api, &author_bytes);
		print_kv_table(&rows);
		println!();
	}

	if common.debug_pallets {
		println!();
		println!("Runtime pallets");
		println!("--------------");
		print_pallets(&api, common.debug_pallet_filter.as_deref());
		println!();
	}

	if let Some(ref pallet_name) = common.debug_storage_list {
		println!();
		debug_list_storage(
			&api,
			pallet_name,
			common.debug_storage_filter.as_deref(),
		);
		println!();
	}

	if let Some(ref args) = common.debug_decode_storage {
		if args.len() == 2 {
			println!();
			debug_decode_plain_storage(
				&api,
				&args[0],
				&args[1],
				common.debug_decode_max_depth,
				common.debug_decode_max_items,
			);
			println!();
		} else {
			eprintln!(
				"debug-decode-storage: expected 2 arguments (<PALLET> <ITEM>), got {}",
				args.len()
			);
		}
	}

	if let Some(ref args) = common.debug_storage {
		if args.len() == 2 {
			println!();
			debug_read_plain_storage(&api, &args[0], &args[1]);
			println!();
		} else {
			eprintln!("debug-storage: expected 2 arguments (<PALLET> <ITEM>), got {}", args.len());
		}
	}

	loop {
		let auths = fetch_authorities(&api)?;
		let current_hash = hash_authorities(&auths);
		let current_hash_hex = hex32(current_hash);

		let changed = prev_hash.is_none()
			|| prev_hash.unwrap() != current_hash
			|| prev_len != auths.len();

		let mut screen_cleared = false;
		if live_update && changed {
			// Re-render the whole screen so output doesn't keep appending (TTY + --watch).
			print!("\r\x1b[2K\x1b[2J\x1b[H{banner}");
			let _ = std::io::stdout().flush();
			waiting_notice_printed = false;
			screen_cleared = true;
		}

		if changed {
			if !live_update && is_tty && waiting_notice_printed {
				println!();
			}
			waiting_notice_printed = false;
				if prev_hash.is_some() {
					println!();
					println!("--------------------------------------------------------------");
					println!(
						"{} (len {} -> {})",
						colors.epoch(i18n.pick("authority set changed", "Authorityセットが更新されました")),
						prev_len,
						auths.len()
					);
				}
			prev_hash = Some(current_hash);
			prev_len = auths.len();
		}

		let slot_dur_ms: u64 = api
			.get_constant("Aura", "SlotDuration")
			.map_err(|e| anyhow!("{e:?}"))?;
		let ts_ms: u64 = api
			.get_storage("Timestamp", "Now", None)
			.map_err(|e| anyhow!("{e:?}"))?
			.unwrap_or(0);
		let best_hash = api
			.get_block_hash(None)
			.map_err(|e| anyhow!("{e:?}"))?
			.ok_or_else(|| anyhow!("no best head"))?;
		let best_header = api
			.get_header(Some(best_hash))
			.map_err(|e| anyhow!("{e:?}"))?
			.ok_or_else(|| anyhow!("no best header"))?;

		// Prefer the real Aura slot from the block digest; timestamp/slot_duration is only a fallback.
		let latest_slot = aura_slot_from_header(&best_header).unwrap_or_else(|| ts_ms / slot_dur_ms);
		let best_number: u64 = best_header.number.into();
		let epoch_idx = latest_slot / epoch_size;
		let start_slot = epoch_idx * epoch_size;
		let slots_to_scan = epoch_size;
		let epoch_end_slot = start_slot + epoch_size.saturating_sub(1);

		let epoch_switched = prev_epoch.is_none() || prev_epoch.unwrap() != epoch_idx;
		if epoch_switched {
			pending_next_committee_print = true;
			next_preview_printed = false;
		}

		if live_update && (changed || epoch_switched) && !screen_cleared {
			// Clear before printing the new session/epoch section.
			print!("\r\x1b[2K\x1b[2J\x1b[H{banner}");
			let _ = std::io::stdout().flush();
			waiting_notice_printed = false;
		}

		if changed || epoch_switched {
			if !live_update && is_tty && waiting_notice_printed {
				println!();
			}
			waiting_notice_printed = false;

			let paren = format!(
				"({}:{} / {}:{})",
				i18n.pick("start_slot", "開始スロット"),
				start_slot,
				i18n.pick("end_slot", "終了スロット"),
				epoch_end_slot
			);
			println!(
				"{}:{} {}",
				i18n.pick("epoch", "エポック"),
				colors.epoch(epoch_idx.to_string()),
				colors.dim(paren)
			);

			if let Some(ref c) = conn {
				db_upsert_epoch_info(c, epoch_idx, start_slot, epoch_end_slot, &current_hash_hex, auths.len())?;
			}

			let mut rows: Vec<(String, String)> = Vec::new();
			rows.push(("author".to_string(), colors.author(&author_hex)));

				// NOTE: `--show-next-active-set` is intentionally disabled for now because the target
				// runtime does not expose the necessary Session storage items.

			if let (Some(sc), Some(http)) = (sidechain_pubkey.as_deref(), ariadne_client.as_ref()) {
				let status = jsonrpc_http_call(
					http,
					&common.ariadne_endpoint,
					"sidechain_getStatus",
					Value::Array(vec![]),
				)
				.ok();

				let main_epoch = status
					.as_ref()
					.and_then(|v| v.get("mainchain"))
					.and_then(|v| v.get("epoch"))
					.and_then(|v| v.as_u64());

				if let Some(main_epoch) = main_epoch {
					match fetch_registration_status(http, &common.ariadne_endpoint, sc, main_epoch) {
						Ok((lovelace, is_valid)) => {
							let ada = format_ada_from_lovelace(lovelace);
							rows.push((
								i18n.pick("ADA Stake", "ADA委任量").to_string(),
								format!("{ada} ADA ({lovelace} lovelace)"),
							));
							let label = if is_valid {
								colors.ok(i18n.pick("Registered", "登録済み"))
							} else {
								colors.error(i18n.pick("Not registered", "未登録"))
							};
							rows.push((
								i18n.pick("Registration", "登録").to_string(),
								format!("{is_valid} ({label})"),
							));
						}
						Err(e) => {
							eprintln!(
								"{}: {}",
								colors.dim(i18n.pick("registration check failed", "登録チェックに失敗しました")),
								colors.dim(e.to_string())
							);
						}
					}
				} else {
					eprintln!(
						"{}",
						colors.dim(i18n.pick(
							"registration check skipped (failed to read mainchain epoch)",
							"登録チェックをスキップしました（mainchain epoch を取得できません）",
						))
					);
				}
			}

			cached_epoch_rows = Some(rows.clone());
			print_kv_table(&rows);
			println!();
		}

				// (progress is rendered in the waiting section, so it appears under the waiting line)
		let author_present = author_in_authorities(&author_bytes, &auths);
		let author_present_changed =
			prev_author_present.is_none() || prev_author_present.unwrap() != author_present;
		prev_author_present = Some(author_present);

				if !author_present {
					current_my_slots.clear();
					prev_schedule_view_hash = None;
						if changed || author_present_changed || prev_epoch.is_none() || prev_epoch.unwrap() != epoch_idx {
							eprintln!(
								"{}",
								colors.error(i18n.pick(
									"Nothing scheduled for this session.",
									"このセッションにスケジュールはありません",
								))
							);
						}
					prev_epoch = Some(epoch_idx);
					if pending_next_committee_print {
						pending_next_committee_print = false;
						println!();
						// Next epoch committee preview (your assigned slots only)
						let next_start_slot = (epoch_idx + 1) * epoch_size;
						print_next_committee_for_author(
							&i18n,
							&colors,
							&api,
							&author_bytes,
							latest_slot,
							ts_ms,
							slot_dur_ms,
							next_start_slot,
							&out_tz,
							&utc_tz,
						);
					}
				} else {
					current_my_slots =
						compute_my_slots(&auths, &author_bytes, start_slot, slots_to_scan);
					let my_hash = schedule_hash(&current_my_slots);
					let my_changed =
						prev_my_schedule_hash.is_none() || prev_my_schedule_hash.unwrap() != my_hash;
					let epoch_changed = epoch_switched;

					if my_changed || epoch_changed {
						if !live_update && is_tty && waiting_notice_printed {
							println!();
						}
						waiting_notice_printed = false;
						prev_my_schedule_hash = Some(my_hash);
						prev_epoch = Some(epoch_idx);

						let planned: Vec<(u64, String)> = current_my_slots
							.iter()
							.map(|slot| {
								let ts = ts_ms as i64
									+ ((*slot as i64 - latest_slot as i64) * slot_dur_ms as i64);
								(*slot, format_ts(ts, &utc_tz))
							})
							.collect();

						if let Some(ref mut c) = conn {
							db_insert_schedule(c, epoch_idx, &planned)?;
						}

						let planned_by_slot: HashMap<u64, String> =
							planned.iter().map(|(s, t)| (*s, t.clone())).collect();

						let schedule_rows: Vec<ScheduleRow> = if let Some(ref c) = conn {
							let fetched = db_fetch_schedule_rows(c, &current_my_slots)?;
							let mut by_slot: HashMap<u64, ScheduleRow> = HashMap::new();
							for r in fetched {
								by_slot.insert(r.slot, r);
							}
							current_my_slots
								.iter()
								.map(|slot| {
									by_slot.get(slot).cloned().unwrap_or_else(|| ScheduleRow {
										slot: *slot,
										planned_time_utc: planned_by_slot
											.get(slot)
											.cloned()
											.unwrap_or_else(|| "-".to_string()),
										status: "schedule".to_string(),
										block_number: None,
										block_hash: None,
										produced_time_utc: None,
									})
								})
								.collect()
						} else {
							current_my_slots
								.iter()
								.map(|slot| ScheduleRow {
									slot: *slot,
									planned_time_utc: planned_by_slot
										.get(slot)
										.cloned()
										.unwrap_or_else(|| "-".to_string()),
									status: "schedule".to_string(),
									block_number: None,
									block_hash: None,
									produced_time_utc: None,
								})
								.collect()
						};

						prev_schedule_view_hash = Some(schedule_rows_hash(&schedule_rows));

						println!(
							"{}: {}",
							i18n.pick("Current epoch Schedule", "現在のエポックのスケジュール"),
							colors.epoch(epoch_idx.to_string())
						);
						println!("-------------------------");
								for (idx, row) in schedule_rows.iter().enumerate() {
									let dt_utc = parse_rfc3339_utc(&row.planned_time_utc);
									let out_ts = dt_utc
										.map(|dt| colors.time(format_dt(dt, &out_tz)))
								.unwrap_or_else(|| "-".to_string());
							let utc_ts = dt_utc
								.map(|dt| format_dt(dt, &utc_tz))
								.unwrap_or_else(|| "-".to_string());

							let status = status_tag(&colors, &row.status);
							println!(
								"#{idx1} slot {}: {} (UTC {}){}",
								colors.slot(row.slot.to_string()),
								out_ts,
								colors.dim(utc_ts),
								status,
								idx1 = idx + 1
							);
						}
						println!("{}={}", i18n.pick("Total", "合計"), schedule_rows.len());

						if pending_next_committee_print {
							pending_next_committee_print = false;
							println!();
							// Next epoch committee preview (your assigned slots only)
							let next_start_slot = (epoch_idx + 1) * epoch_size;
							print_next_committee_for_author(
								&i18n,
								&colors,
								&api,
								&author_bytes,
								latest_slot,
								ts_ms,
								slot_dur_ms,
								next_start_slot,
								&out_tz,
								&utc_tz,
							);
							next_preview_printed = true;
						}
					}
				}

			// Mint detection: scan new best blocks since last check and mark blocks produced by this author.
			// This avoids missing mint events when the tool sleeps between polls.
			if best_number > last_best_number {
				for n in (last_best_number + 1)..=best_number {
					let bn_u32: u32 = n.try_into().map_err(|_| anyhow!("best block number {n} does not fit u32"))?;
					let Some(h) = api.get_block_hash(Some(bn_u32)).map_err(|e| anyhow!("{e:?}"))? else {
						continue;
					};
					let Some(hdr) = api.get_header(Some(h)).map_err(|e| anyhow!("{e:?}"))? else {
						continue;
					};
					let Some(slot) = aura_slot_from_header(&hdr) else {
						continue;
					};
					let auths_for_slot = authorities_at(&api, hdr.parent_hash).unwrap_or_else(|_| auths.clone());
					if auths_for_slot.is_empty() {
						continue;
					}
					let expected = &auths_for_slot[(slot as usize) % auths_for_slot.len()];
					let expected_bytes: &[u8] = expected.as_ref();
					if expected_bytes != author_bytes.as_slice() {
						continue;
					}
					if let Some(ref c) = conn {
						let block_hash_str = format!("{h:?}");
						let produced_time_utc = block_time_utc(&api, h);
						db_upsert_minted_block(c, slot, slot / epoch_size, n, &block_hash_str, &produced_time_utc)?;
					}
				}
				last_best_number = best_number;
			}

			// Finality: scan new finalized blocks since last check and update scheduled slots.
			let _ = scan_new_finalized_blocks(&api, conn.as_ref(), &mut last_finalized_number)?;

				// Watch SQLite schedule status changes and refresh the displayed schedule.
				if author_present && !current_my_slots.is_empty() {
					if let Some(ref c) = conn {
						let schedule_rows = db_fetch_schedule_rows(c, &current_my_slots)?;
						let new_hash = schedule_rows_hash(&schedule_rows);
						let changed = prev_schedule_view_hash.map(|h| h != new_hash).unwrap_or(true);
						if changed {
							prev_schedule_view_hash = Some(new_hash);
							waiting_notice_printed = false;
							if live_update {
								print!("\r\x1b[2K\x1b[2J\x1b[H{banner}");
								let _ = std::io::stdout().flush();

								let paren = format!(
									"({}:{} / {}:{})",
									i18n.pick("start_slot", "開始スロット"),
									start_slot,
									i18n.pick("end_slot", "終了スロット"),
									epoch_end_slot
								);
								println!(
									"{}:{} {}",
									i18n.pick("epoch", "エポック"),
									colors.epoch(epoch_idx.to_string()),
									colors.dim(paren)
								);
								if let Some(ref rows) = cached_epoch_rows {
									print_kv_table(rows);
									println!();
								}
							}

							println!(
								"{}: {}",
								i18n.pick("Current epoch Schedule", "現在のエポックのスケジュール"),
								colors.epoch(epoch_idx.to_string())
							);
							println!("-------------------------");
							for (idx, row) in schedule_rows.iter().enumerate() {
								let dt_utc = parse_rfc3339_utc(&row.planned_time_utc);
								let out_ts = dt_utc
									.map(|dt| colors.time(format_dt(dt, &out_tz)))
									.unwrap_or_else(|| "-".to_string());
								let utc_ts = dt_utc
									.map(|dt| format_dt(dt, &utc_tz))
									.unwrap_or_else(|| "-".to_string());

								let status = status_tag(&colors, &row.status);
								println!(
									"#{idx1} slot {}: {} (UTC {}){}",
									colors.slot(row.slot.to_string()),
									out_ts,
									colors.dim(utc_ts),
									status,
										idx1 = idx + 1
									);
								}
								println!("{}={}", i18n.pick("Total", "合計"), schedule_rows.len());

								if live_update && next_preview_printed {
									println!();
									let next_start_slot = (epoch_idx + 1) * epoch_size;
									print_next_committee_for_author(
										&i18n,
										&colors,
										&api,
										&author_bytes,
										latest_slot,
										ts_ms,
										slot_dur_ms,
										next_start_slot,
										&out_tz,
										&utc_tz,
									);
								}
							}
						}
					}

				if !common.watch {
					break;
				}

			if !waiting_notice_printed {
				waiting_notice_printed = true;
				println!();
				println!(
					"{} (next_epoch={})",
					i18n.pick("Waiting for next session...", "次のセッション待ち..."),
					epoch_idx + 1
				);
			}

			// Poll the chain once per slot (approx 1s) so mint/finality updates are not delayed.
			if is_tty {
				let cur = latest_slot.saturating_sub(start_slot);
				let denom = epoch_size.max(1);
				let pct = ((cur.saturating_mul(100)) / denom).min(100) as u8;
				if waiting_progress_tick % 5 == 0 {
					print_progress(
						true,
						&colors,
						i18n.pick("progress", "進捗"),
						pct,
						latest_slot,
						epoch_end_slot,
					);
				}
			}

			waiting_progress_tick = waiting_progress_tick.wrapping_add(1);
			std::thread::sleep(Duration::from_secs(1));
			continue;
		}

	Ok(())
}

fn main() -> anyhow::Result<()> {
	let cli = Cli::parse();
	match cli.command {
		Command::Block(common) => run(common),
		Command::Log(args) => run_block(args),
	}
}
