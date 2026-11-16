use std::{
	collections::BTreeMap,
	fmt::Write as _,
	net::IpAddr,
	path::Path,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::FutureExt;
use ruma::{
	DeviceId, Mxc, OwnedDeviceId, OwnedMxcUri, OwnedOneTimeKeyId, OwnedRoomId, OwnedUserId,
	UserId,
	api::client::filter::FilterDefinition,
	encryption::OneTimeKey,
	events::{
		GlobalAccountDataEventType,
		push_rules::{PushRulesEvent, PushRulesEventContent},
	},
	push::{
		Action, NewConditionalPushRule, NewPatternedPushRule, NewPushRule, NewSimplePushRule,
		PushCondition, RuleKind, Ruleset,
	},
	serde::Raw,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json, value::to_raw_value};
use tuwunel_core::{
	Err, Result, err, utils::content_disposition::make_content_disposition, warn,
};
use tuwunel_service::{
	profile::Propagation,
	users::{PASSWORD_SENTINEL, device::TOKEN_LENGTH},
};

use crate::{Context, admin_command};

/// Synapse export produced by `scripts/synapse-export.py`.
#[derive(Deserialize)]
struct Export {
	server_name: String,
	users: Vec<ExportUser>,
	#[serde(default)]
	media: Vec<ExportMedia>,
}

#[derive(Deserialize)]
struct ExportUser {
	user_id: OwnedUserId,
	password_hash: Option<String>,
	#[serde(default)]
	admin: bool,
	#[serde(default)]
	deactivated: bool,
	#[serde(default)]
	locked: bool,
	#[serde(default)]
	suspended: bool,
	displayname: Option<String>,
	avatar_url: Option<OwnedMxcUri>,
	#[serde(default)]
	account_data: BTreeMap<String, Value>,
	/// Custom rules, ordered from highest to lowest priority.
	#[serde(default)]
	push_rules: Vec<ExportPushRule>,
	#[serde(default)]
	push_rules_enabled: Vec<ExportPushRuleEnabled>,
	#[serde(default)]
	filters: BTreeMap<String, Value>,
	#[serde(default)]
	devices: Vec<ExportDevice>,
	#[serde(default)]
	cross_signing: ExportCrossSigning,
	#[serde(default)]
	backups: Vec<ExportBackup>,
}

#[derive(Deserialize)]
struct ExportPushRule {
	kind: String,
	rule_id: String,
	#[serde(default)]
	conditions: Value,
	#[serde(default)]
	actions: Value,
	#[serde(default = "default_true")]
	enabled: bool,
}

#[derive(Deserialize)]
struct ExportPushRuleEnabled {
	kind: String,
	rule_id: String,
	enabled: bool,
}

#[derive(Deserialize)]
struct ExportDevice {
	device_id: OwnedDeviceId,
	display_name: Option<String>,
	last_seen_ip: Option<String>,
	#[serde(default)]
	access_tokens: Vec<ExportAccessToken>,
	device_keys: Option<Value>,
	#[serde(default)]
	one_time_keys: BTreeMap<OwnedOneTimeKeyId, Value>,
	#[serde(default)]
	fallback_keys: BTreeMap<OwnedOneTimeKeyId, Value>,
}

#[derive(Deserialize)]
struct ExportAccessToken {
	token: String,
	expires_at_ms: Option<u64>,
	refresh_token: Option<String>,
}

#[derive(Default, Deserialize)]
struct ExportCrossSigning {
	master: Option<Value>,
	self_signing: Option<Value>,
	user_signing: Option<Value>,
}

#[derive(Deserialize)]
struct ExportBackup {
	version: String,
	algorithm: Value,
	#[serde(default)]
	sessions: Vec<ExportBackupSession>,
}

#[derive(Deserialize)]
struct ExportBackupSession {
	room_id: OwnedRoomId,
	session_id: String,
	data: Value,
}

#[derive(Deserialize)]
struct ExportMedia {
	media_id: String,
	user_id: Option<OwnedUserId>,
	content_type: Option<String>,
	upload_name: Option<String>,
	/// Path relative to the export file.
	file: String,
}

#[derive(Default)]
struct Stats {
	users: usize,
	deactivated: usize,
	admins: usize,
	devices: usize,
	access_tokens: usize,
	refresh_tokens: usize,
	skipped_tokens: usize,
	device_keys: usize,
	one_time_keys: usize,
	fallback_keys: usize,
	cross_signing: usize,
	backups: usize,
	backup_sessions: usize,
	account_data: usize,
	push_rules: usize,
	filters: usize,
	media: usize,
	warnings: usize,
}

fn default_true() -> bool { true }

#[admin_command]
pub(super) async fn import_synapse(&self, path: String) -> Result {
	let path = Path::new(&path);
	let export = tokio::fs::read(path)
		.await
		.map_err(|e| err!("Failed to read {path:?}: {e}"))?;

	let export: Export =
		serde_json::from_slice(&export).map_err(|e| err!("Failed to parse {path:?}: {e}"))?;

	let server_name = self.services.globals.server_name();
	if export.server_name != server_name.as_str() {
		return Err!(
			"Export is for {:?} but this server is {server_name:?}.",
			export.server_name
		);
	}

	for user in &export.users {
		if !self.services.globals.user_is_local(&user.user_id) {
			return Err!("Export contains non-local user {}.", user.user_id);
		}

		if self.services.users.exists(&user.user_id).await {
			return Err!(
				"User {} already exists; import requires a fresh database.",
				user.user_id
			);
		}
	}

	let mut stats = Stats::default();
	for user in &export.users {
		import_user(self, user, &mut stats)
			.boxed()
			.await
			.map_err(|e| err!("Failed importing {}: {e}", user.user_id))?;
	}

	// Granting admin joins the admin room, so do it once every account exists.
	for user in export
		.users
		.iter()
		.filter(|user| user.admin && !user.deactivated)
	{
		self.services
			.admin
			.make_user_admin(&user.user_id)
			.boxed()
			.await?;

		stats.admins = stats.admins.saturating_add(1);
	}

	let base = path.parent().unwrap_or_else(|| Path::new("."));
	for media in &export.media {
		import_media(self, base, media, &mut stats).await?;
	}

	let mut out = String::new();
	let Stats {
		users,
		deactivated,
		admins,
		devices,
		access_tokens,
		refresh_tokens,
		skipped_tokens,
		device_keys,
		one_time_keys,
		fallback_keys,
		cross_signing,
		backups,
		backup_sessions,
		account_data,
		push_rules,
		filters,
		media,
		warnings,
	} = stats;

	writeln!(out, "Imported {users} users ({deactivated} deactivated, {admins} admins).")?;
	writeln!(
		out,
		"Devices: {devices}; access tokens: {access_tokens}; refresh tokens: {refresh_tokens}; \
		 skipped tokens: {skipped_tokens}."
	)?;
	writeln!(
		out,
		"Device keys: {device_keys}; one-time keys: {one_time_keys}; fallback keys: \
		 {fallback_keys}; cross-signing users: {cross_signing}."
	)?;
	writeln!(out, "Key backups: {backups} ({backup_sessions} sessions).")?;
	writeln!(
		out,
		"Account data: {account_data}; custom push rules: {push_rules}; filters: {filters}; \
		 media: {media}."
	)?;
	write!(out, "Warnings: {warnings} (see server log).")?;

	self.write_str(&out).await
}

async fn import_user(ctx: &Context<'_>, user: &ExportUser, stats: &mut Stats) -> Result {
	let services = ctx.services;
	let user_id = &user.user_id;

	match (user.deactivated, user.password_hash.as_deref()) {
		| (true, _) => {
			services
				.users
				.create(user_id, None, Some("password"))
				.await?;
			stats.deactivated = stats.deactivated.saturating_add(1);
		},
		| (false, Some(hash)) if !hash.is_empty() => {
			services
				.users
				.create(user_id, None, Some("password"))
				.await?;
			services.users.set_password_hash(user_id, hash);
		},
		| (false, _) => {
			services
				.users
				.create(user_id, Some(PASSWORD_SENTINEL), Some("password"))
				.await?;
		},
	}

	stats.users = stats.users.saturating_add(1);

	if let Some(displayname) = user.displayname.as_deref() {
		services
			.profile
			.set_displayname(user_id, Some(displayname), Some(Propagation::None))
			.await?;
	}

	if let Some(avatar_url) = user.avatar_url.as_deref() {
		services
			.profile
			.set_avatar_url(user_id, Some(avatar_url), Some(Propagation::None))
			.await?;
	}

	if user.locked {
		services
			.users
			.set_locked(user_id, &services.globals.server_user);
	}

	if user.suspended {
		services
			.users
			.set_suspended(user_id, &services.globals.server_user);
	}

	import_push_rules(ctx, user, stats).await?;

	for (event_type, content) in &user.account_data {
		let data = json!({ "type": event_type, "content": content });
		services
			.account_data
			.update(None, user_id, event_type.clone().into(), &data)
			.await?;

		stats.account_data = stats.account_data.saturating_add(1);
	}

	for (filter_id, filter) in &user.filters {
		let Some(filter) = parse::<FilterDefinition>(filter, "filter", user_id, stats) else {
			continue;
		};

		services
			.users
			.put_filter(user_id, filter_id, &filter);

		stats.filters = stats.filters.saturating_add(1);
	}

	if user.deactivated {
		return Ok(());
	}

	for device in &user.devices {
		import_device(ctx, user_id, device, stats).await?;
	}

	let cross_signing = &user.cross_signing;
	if cross_signing.master.is_some() {
		let master = cross_signing
			.master
			.as_ref()
			.map(to_raw)
			.transpose()?;
		let self_signing = cross_signing
			.self_signing
			.as_ref()
			.map(to_raw)
			.transpose()?;
		let user_signing = cross_signing
			.user_signing
			.as_ref()
			.map(to_raw)
			.transpose()?;

		services
			.users
			.add_cross_signing_keys(user_id, &master, &self_signing, &user_signing, false)
			.await?;

		stats.cross_signing = stats.cross_signing.saturating_add(1);
	}

	for backup in &user.backups {
		let algorithm = to_raw(&backup.algorithm)?;
		services
			.key_backups
			.import_backup(user_id, &backup.version, &algorithm)?;

		for session in &backup.sessions {
			services
				.key_backups
				.add_key(
					user_id,
					&backup.version,
					&session.room_id,
					&session.session_id,
					&to_raw(&session.data)?,
				)
				.await?;

			stats.backup_sessions = stats.backup_sessions.saturating_add(1);
		}

		stats.backups = stats.backups.saturating_add(1);
	}

	Ok(())
}

async fn import_device(
	ctx: &Context<'_>,
	user_id: &UserId,
	device: &ExportDevice,
	stats: &mut Stats,
) -> Result {
	let services = ctx.services;
	let device_id: &DeviceId = &device.device_id;
	let client_ip = device
		.last_seen_ip
		.as_deref()
		.and_then(|ip| ip.parse::<IpAddr>().ok());

	let tokens: Vec<_> = device
		.access_tokens
		.iter()
		.filter_map(|token| usable_token(token, stats))
		.collect();

	let (first, rest) = tokens
		.split_first()
		.map_or((None, &[][..]), |(first, rest)| (Some(first), rest));

	services
		.users
		.create_device(
			user_id,
			Some(device_id),
			first.map_or((None, None), |&(token, ttl, _)| (Some(token), ttl)),
			first.and_then(|&(_, _, refresh)| refresh),
			device.display_name.as_deref(),
			client_ip,
		)
		.await?;

	for &(token, ttl, refresh) in rest {
		services
			.users
			.set_access_token(user_id, device_id, token, ttl, refresh)
			.await?;
	}

	stats.devices = stats.devices.saturating_add(1);
	stats.access_tokens = stats.access_tokens.saturating_add(tokens.len());
	stats.refresh_tokens = stats.refresh_tokens.saturating_add(
		tokens
			.iter()
			.filter(|(_, _, refresh)| refresh.is_some())
			.count(),
	);

	if let Some(device_keys) = device.device_keys.as_ref() {
		services
			.users
			.add_device_keys(user_id, device_id, &to_raw(device_keys)?)
			.await;

		stats.device_keys = stats.device_keys.saturating_add(1);
	}

	let one_time_keys: BTreeMap<OwnedOneTimeKeyId, Raw<OneTimeKey>> = device
		.one_time_keys
		.iter()
		.map(|(key_id, key)| Ok((key_id.clone(), to_raw(key)?)))
		.collect::<Result<_>>()?;

	if !one_time_keys.is_empty() {
		services
			.users
			.add_one_time_keys(
				user_id,
				device_id,
				&one_time_keys,
				services.config.one_time_key_limit,
			)
			.await?;

		stats.one_time_keys = stats
			.one_time_keys
			.saturating_add(one_time_keys.len());
	}

	let fallback_keys: BTreeMap<OwnedOneTimeKeyId, Raw<OneTimeKey>> = device
		.fallback_keys
		.iter()
		.map(|(key_id, key)| Ok((key_id.clone(), to_raw(key)?)))
		.collect::<Result<_>>()?;

	if !fallback_keys.is_empty() {
		services
			.users
			.add_fallback_keys(
				user_id,
				device_id,
				fallback_keys
					.iter()
					.map(|(key_id, key)| (&**key_id, key)),
			)
			.await?;

		stats.fallback_keys = stats
			.fallback_keys
			.saturating_add(fallback_keys.len());
	}

	Ok(())
}

/// Returns the token with its remaining lifetime, or `None` when it can no
/// longer be used.
fn usable_token<'a>(
	token: &'a ExportAccessToken,
	stats: &mut Stats,
) -> Option<(&'a str, Option<Duration>, Option<&'a str>)> {
	let refresh = token.refresh_token.as_deref();
	if token.token.len() < TOKEN_LENGTH {
		warn!("Skipping access token shorter than {TOKEN_LENGTH} characters.");
		stats.skipped_tokens = stats.skipped_tokens.saturating_add(1);
		stats.warnings = stats.warnings.saturating_add(1);
		return None;
	}

	let Some(expires_at_ms) = token.expires_at_ms else {
		return Some((&token.token, None, refresh));
	};

	let now_ms = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis();

	let remaining = u128::from(expires_at_ms).saturating_sub(now_ms);
	match (remaining, refresh) {
		// Expired but refreshable: keep it so the client can refresh.
		| (0, Some(_)) => Some((&token.token, Some(Duration::from_secs(1)), refresh)),
		| (0, None) => {
			stats.skipped_tokens = stats.skipped_tokens.saturating_add(1);
			None
		},
		| (remaining, _) => {
			let remaining = u64::try_from(remaining).unwrap_or(u64::MAX);
			Some((&token.token, Some(Duration::from_millis(remaining)), refresh))
		},
	}
}

async fn import_push_rules(ctx: &Context<'_>, user: &ExportUser, stats: &mut Stats) -> Result {
	let user_id = &user.user_id;
	let mut ruleset = Ruleset::server_default(user_id);

	// Each insert lands at the top of its kind, so go from lowest priority up.
	for rule in user.push_rules.iter().rev() {
		let Some(new_rule) = new_push_rule(rule, user_id, stats) else {
			continue;
		};

		if let Err(e) = ruleset.insert(new_rule, None, None) {
			warn!(%user_id, rule_id = rule.rule_id, "Skipping push rule: {e}");
			stats.warnings = stats.warnings.saturating_add(1);
			continue;
		}

		if !rule.enabled {
			ruleset
				.set_enabled(RuleKind::from(rule.kind.as_str()), &rule.rule_id, false)
				.ok();
		}

		stats.push_rules = stats.push_rules.saturating_add(1);
	}

	for rule in &user.push_rules_enabled {
		let kind = RuleKind::from(rule.kind.as_str());
		if let Err(e) = ruleset.set_enabled(kind, &rule.rule_id, rule.enabled) {
			warn!(%user_id, rule_id = rule.rule_id, "Skipping push rule toggle: {e}");
			stats.warnings = stats.warnings.saturating_add(1);
		}
	}

	let event = PushRulesEvent {
		content: PushRulesEventContent { global: ruleset },
	};

	ctx.services
		.account_data
		.update(
			None,
			user_id,
			GlobalAccountDataEventType::PushRules
				.to_string()
				.into(),
			&serde_json::to_value(event)?,
		)
		.await
}

fn new_push_rule(
	rule: &ExportPushRule,
	user_id: &UserId,
	stats: &mut Stats,
) -> Option<NewPushRule> {
	let actions = parse::<Vec<Action>>(&rule.actions, "push rule actions", user_id, stats)?
		.into_iter()
		.collect();

	let kind = rule.kind.as_str();
	let conditions: Vec<PushCondition> =
		if matches!(kind, "override" | "underride" | "content") && !rule.conditions.is_null() {
			parse(&rule.conditions, "push rule conditions", user_id, stats)?
		} else {
			Vec::new()
		};

	let rule_id = rule.rule_id.as_str();
	let new_rule = match kind {
		| "override" => NewPushRule::Override(NewConditionalPushRule::new(
			rule_id.into(),
			conditions.into_iter().collect(),
			actions,
		)),
		| "underride" => NewPushRule::Underride(NewConditionalPushRule::new(
			rule_id.into(),
			conditions.into_iter().collect(),
			actions,
		)),
		| "content" => {
			let pattern = conditions
				.into_iter()
				.find_map(|condition| match condition {
					| PushCondition::EventMatch(event_match) => Some(event_match.pattern),
					| _ => None,
				})?;

			NewPushRule::Content(NewPatternedPushRule::new(
				rule_id.into(),
				pattern.as_str().into(),
				actions,
			))
		},
		| "room" => NewPushRule::Room(NewSimplePushRule::new(rule_id.try_into().ok()?, actions)),
		| "sender" =>
			NewPushRule::Sender(NewSimplePushRule::new(rule_id.try_into().ok()?, actions)),
		| _ => {
			warn!(%user_id, rule_id, kind, "Skipping push rule of unsupported kind.");
			stats.warnings = stats.warnings.saturating_add(1);
			return None;
		},
	};

	Some(new_rule)
}

async fn import_media(
	ctx: &Context<'_>,
	base: &Path,
	media: &ExportMedia,
	stats: &mut Stats,
) -> Result {
	let file_path = base.join(&media.file);
	let file = match tokio::fs::read(&file_path).await {
		| Ok(file) => file,
		| Err(e) => {
			warn!(media_id = media.media_id, "Skipping media, cannot read {file_path:?}: {e}");
			stats.warnings = stats.warnings.saturating_add(1);
			return Ok(());
		},
	};

	let mxc = Mxc {
		server_name: ctx.services.globals.server_name(),
		media_id: &media.media_id,
	};

	let content_type = media.content_type.as_deref();
	let content_disposition =
		make_content_disposition(None, content_type, media.upload_name.as_deref());

	ctx.services
		.media
		.create(&mxc, media.user_id.as_deref(), Some(&content_disposition), content_type, &file)
		.await?;

	stats.media = stats.media.saturating_add(1);

	Ok(())
}

fn parse<T: DeserializeOwned>(
	value: &Value,
	what: &str,
	user_id: &UserId,
	stats: &mut Stats,
) -> Option<T> {
	serde_json::from_value(value.clone())
		.inspect_err(|e| {
			warn!(%user_id, "Skipping invalid {what}: {e}");
			stats.warnings = stats.warnings.saturating_add(1);
		})
		.ok()
}

fn to_raw<T>(value: &Value) -> Result<Raw<T>> { Ok(Raw::from_json(to_raw_value(value)?)) }
