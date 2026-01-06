use clap::Parser;
use sha2::{Digest, Sha256};
use std::io::IsTerminal;
use std::io::Write;
use std::{path::Path, time::Duration};
use substrate_api_client::{
	ac_primitives::{sr25519, DefaultRuntimeConfig},
	rpc::TungsteniteRpcClient,
	Api, GetChainInfo, GetStorage,
};
use substrate_api_client::rpc::Request;
use anyhow::anyhow;
use chrono::{FixedOffset, Local, Utc};
use rusqlite::{params, Connection};
use sp_runtime::generic::DigestItem;

#[derive(Parser)]
#[command(name = "mblog", version)]
struct Args {
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
    #[arg(long)]
    /// Enable continuous monitoring mode (run forever)
    watch: bool,
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
	let dt_utc = chrono::DateTime::<Utc>::from_timestamp_millis(ts_ms).unwrap();
	match tz {
		OutputTz::Utc => dt_utc.to_rfc3339(),
		OutputTz::Local => dt_utc.with_timezone(&Local).to_rfc3339(),
		OutputTz::ForcedLocal => dt_utc.with_timezone(&Local).to_rfc3339(),
		OutputTz::Fixed(off) => dt_utc.with_timezone(off).to_rfc3339(),
	}
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

fn fetch_authorities(
	api: &Api<DefaultRuntimeConfig, TungsteniteRpcClient>,
) -> anyhow::Result<Vec<sr25519::Public>> {
	let res: Option<Vec<sr25519::Public>> = api
		.get_storage("Aura", "Authorities", None)
		.map_err(|e| anyhow!("{e:?}"))?;
	Ok(res.unwrap_or_default())
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

fn main() -> anyhow::Result<()> {
		    let args = Args::parse();
		    let i18n = I18n::new(args.lang);
				println!();
				println!(
					" Midnight-blocklog - {}: {}",
					i18n.pick("Version", "バージョン"),
					env!("CARGO_PKG_VERSION")
				);
				println!("--------------------------------------------------------------");
				let colors = Colors::new(args.color);
				let is_tty = std::io::stdout().is_terminal();
				let mut conn = if args.no_store {
					None
				} else {
				let conn = Connection::open(&args.db)?;
				ensure_db(&conn)?;
				Some(conn)
			};
	let author_hex =
		detect_aura_pubkey_from_keystore(Path::new(&args.keystore_path))?;
	let author_bytes =
		parse_pubkey_hex(&author_hex).map_err(|e| anyhow!("invalid aura pubkey from keystore: {e}"))?;
	let out_tz = parse_output_tz(&args.tz)?;
	let utc_tz = OutputTz::Utc;

    let client = TungsteniteRpcClient::new(&args.ws, 3)
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

	let epoch_size = args.epoch_size as u64;

	let mut prev_hash: Option<[u8; 32]> = None;
	let mut prev_len: usize = 0;
	let mut prev_author_present: Option<bool> = None;
	let mut prev_my_schedule_hash: Option<[u8; 32]> = None;
	let mut prev_epoch: Option<u64> = None;
	let mut printed_identity: bool = false;
	let mut waiting_notice_printed: bool = false;
	// Do not backfill from genesis on startup; initialize cursors from the current chain state.
	let mut last_best_hash: Option<sp_core::H256> = api
		.get_block_hash(None)
		.map_err(|e| anyhow!("{e:?}"))?;
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

	loop {
		let auths = fetch_authorities(&api)?;
		let current_hash = hash_authorities(&auths);
		let current_hash_hex = hex32(current_hash);

		let changed = prev_hash.is_none()
			|| prev_hash.unwrap() != current_hash
			|| prev_len != auths.len();

		if changed {
			if is_tty && waiting_notice_printed {
				println!();
			}
			waiting_notice_printed = false;
				if prev_hash.is_some() {
					println!(
						"{} (len {} -> {})",
						colors.epoch(i18n.pick("authority set changed", "Authorityセットが更新されました")),
						prev_len,
						auths.len()
					);
					println!();
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

					if changed || epoch_switched {
						if is_tty && waiting_notice_printed {
							println!();
						}
						waiting_notice_printed = false;
							println!(
								"{}:{} / {}:{} / {}:{}",
								i18n.pick("epoch", "エポック"),
								colors.epoch(epoch_idx.to_string()),
								i18n.pick("start_slot", "開始スロット"),
								colors.range(start_slot.to_string()),
								i18n.pick("end_slot", "終了スロット"),
								colors.range(epoch_end_slot.to_string())
					);

				if let Some(ref c) = conn {
					db_upsert_epoch_info(c, epoch_idx, start_slot, epoch_end_slot, &current_hash_hex, auths.len())?;
				}
			}

			if !printed_identity {
				printed_identity = true;
				println!("author={}", colors.author(&author_hex));
				println!();
			}

				// (progress is rendered in the waiting section, so it appears under the waiting line)
		let author_present = author_in_authorities(&author_bytes, &auths);
		let author_present_changed =
			prev_author_present.is_none() || prev_author_present.unwrap() != author_present;
		prev_author_present = Some(author_present);

			if !author_present {
					if changed || author_present_changed || prev_epoch.is_none() || prev_epoch.unwrap() != epoch_idx {
						eprintln!(
							"epoch={epoch_idx}, authorities={}; {}",
							auths.len(),
							i18n.pick(
								"Nothing scheduled for this session.",
								"このセッションにスケジュールはありません",
							)
						);
					}
				prev_epoch = Some(epoch_idx);
			} else {
				let my_slots = compute_my_slots(&auths, &author_bytes, start_slot, slots_to_scan);
				let my_hash = schedule_hash(&my_slots);
					let my_changed = prev_my_schedule_hash.is_none() || prev_my_schedule_hash.unwrap() != my_hash;
					let epoch_changed = epoch_switched;

							if my_changed || epoch_changed {
								if is_tty && waiting_notice_printed {
									println!();
								}
								waiting_notice_printed = false;
								prev_my_schedule_hash = Some(my_hash);
								prev_epoch = Some(epoch_idx);

							let mut idx: usize = 0;

						if let Some(ref mut c) = conn {
							let planned: Vec<(u64, String)> = my_slots
								.iter()
								.map(|slot| {
								let ts = ts_ms as i64
									+ ((*slot as i64 - latest_slot as i64) * slot_dur_ms as i64);
								(*slot, format_ts(ts, &utc_tz))
							})
							.collect();
						db_insert_schedule(c, epoch_idx, &planned)?;
					}
						println!(
							"{}",
							i18n.pick("Your Block Schedule List", "あなたのブロック生成スケジュール")
						);
						println!("-------------------------");
					for slot in &my_slots {
						idx += 1;
						let ts = ts_ms as i64 + ((*slot as i64 - latest_slot as i64) * slot_dur_ms as i64);
						let out_ts = colors.time(format_ts(ts, &out_tz));
						let utc_ts = format_ts(ts, &utc_tz);
						println!(
							"#{idx} slot {}: {} (UTC {})",
							colors.slot(slot.to_string()),
							out_ts,
							colors.dim(utc_ts)
						);
					}
					println!("{}={}", i18n.pick("Total", "合計"), my_slots.len());
				}
			}

			// Mint detection (best head): when a new head appears and its slot belongs to this author.
			if last_best_hash.map(|h| h != best_hash).unwrap_or(true) {
				last_best_hash = Some(best_hash);
				if let Some(slot) = aura_slot_from_header(&best_header) {
					let expected = &auths[(slot as usize) % auths.len()];
					let expected_bytes: &[u8] = expected.as_ref();
					if expected_bytes == author_bytes.as_slice() {
						if let Some(ref c) = conn {
							let block_hash_str = format!("{best_hash:?}");
							let produced_time_utc = block_time_utc(&api, best_hash);
							db_update_block_status(
								c,
								slot,
								best_number,
								&block_hash_str,
								&produced_time_utc,
								"mint",
							)?;
						}
					}
				}
			}

			// Finality: scan new finalized blocks since last check and update scheduled slots.
			if let Some(finalized_hash) = api
				.get_finalized_head()
				.map_err(|e| anyhow!("{e:?}"))?
			{
				if let Some(finalized_header) = api
					.get_header(Some(finalized_hash))
					.map_err(|e| anyhow!("{e:?}"))?
				{
					let finalized_number: u64 = finalized_header.number.into();
					if finalized_number > last_finalized_number {
						for n in (last_finalized_number + 1)..=finalized_number {
							let bn_u32: u32 = n
								.try_into()
								.map_err(|_| anyhow!("finalized block number {n} does not fit u32"))?;
							let Some(h) = api
								.get_block_hash(Some(bn_u32))
								.map_err(|e| anyhow!("{e:?}"))?
							else {
								continue;
							};
							let Some(hdr) = api.get_header(Some(h)).map_err(|e| anyhow!("{e:?}"))? else {
								continue;
							};
							let Some(slot) = aura_slot_from_header(&hdr) else {
								continue;
							};
							if let Some(ref c) = conn {
								let block_hash_str = format!("{h:?}");
								let produced_time_utc = block_time_utc(&api, h);
								db_update_block_status(
									c,
									slot,
									n,
									&block_hash_str,
									&produced_time_utc,
									"finality",
								)?;
							}
						}
						last_finalized_number = finalized_number;
					}
				}
			}

			if !args.watch {
				break;
			}
				let next_epoch_start_slot = (epoch_idx + 1) * epoch_size;
				let delta_slots = next_epoch_start_slot.saturating_sub(latest_slot).max(1);
				let delta_ms = delta_slots.saturating_mul(slot_dur_ms);
				let remaining_secs = (delta_ms / 1000).max(1);

					if !waiting_notice_printed {
						waiting_notice_printed = true;
						println!();
						println!(
							"{} (next_epoch={})",
							i18n.pick("Waiting for next session...", "次のセッション待ち..."),
							epoch_idx + 1
						);
					}

				// Avoid sleeping for very long periods so we can still react if the node stalls.
				let sleep_secs = remaining_secs.min(600).max(1);
				if is_tty {
					// Update progress line in realtime without extra RPC calls.
					let slot_dur_ms = slot_dur_ms.max(1);
					for elapsed in 0..sleep_secs {
						let est_slot = latest_slot.saturating_add((elapsed * 1000) / slot_dur_ms);
						let cur = est_slot.saturating_sub(start_slot);
						let denom = epoch_size.max(1);
						let pct = ((cur.saturating_mul(100)) / denom).min(100) as u8;
						// Always redraw once per second so the current slot display advances even if the percentage doesn't.
							print_progress(
								true,
								&colors,
								i18n.pick("progress", "進捗"),
								pct,
								est_slot,
								epoch_end_slot,
							);
							std::thread::sleep(Duration::from_secs(1));
						}
				} else {
					// Non-TTY: keep logs clean, and avoid extra CPU usage.
					std::thread::sleep(Duration::from_secs(sleep_secs));
				}
			}

    Ok(())
}
