#![cfg(test)]

use std::{
	fs::{create_dir_all, remove_dir_all, write},
	path::PathBuf,
	process::id as process_id,
	time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tuwunel::{Args, Runtime, Server, async_run, async_start, async_stop};
use tuwunel_admin::{fini, init};
use tuwunel_core::{
	Err, Result, err,
	ruma::{
		DeviceId, Mxc, OneTimeKeyAlgorithm, RoomId, UInt, UserId,
		events::{GlobalAccountDataEventType, push_rules::PushRulesEvent},
		push::{AnyPushRuleRef, RuleKind},
	},
	utils::hash,
};
use tuwunel_service::{Services, users::device::RefreshToken};

const PASSWORD: &str = "temp123";
// Produced by Synapse (python bcrypt, 12 rounds) for PASSWORD.
const PASSWORD_HASH: &str = "$2b$12$SBCex8KQ5tjrIm7U4Vt6h.eNf7cF3/GJTcC/oaRH9/VrLnK5RQWJ6";
const ACCESS_TOKEN: &str = "syt_YWxpY2U_kQhCwYnTzZbVxXpLmNoP_2a9Fk1";
const EXPIRED_TOKEN: &str = "syt_YWxpY2U_expiredExpiredExpired_0Abcde";
const REFRESHABLE_TOKEN: &str = "syt_YWxpY2U_refreshableRefreshable_1Bcdef";
const REFRESH_TOKEN: &str = "syr_YWxpY2U_refreshRefreshRefresh_2Cdefg";
const MASTER_KEY: &str = "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk";
const SELF_SIGNING_KEY: &str = "Ma6O/1kfNtjXOwXEOvPYgKUPn5a1qvb7Dr7LzzzmsPw";
const USER_SIGNING_KEY: &str = "QpwdjVBvbcoibRV4KsgZxqHsY0SCGAWZjnxHb5tcCeU";

struct TestDir(PathBuf);

impl Drop for TestDir {
	fn drop(&mut self) { remove_dir_all(&self.0).ok(); }
}

#[test]
fn synapse_import_keeps_sessions() -> Result {
	let root =
		TestDir(PathBuf::from(format!("/tmp/tuwunel-test-synapse-import-{}", process_id())));
	let db_path = root.0.join("db");
	let export_dir = root.0.join("export");
	create_dir_all(export_dir.join("local_content/av/at")).map_err(|e| err!("{e}"))?;
	write(export_dir.join("local_content/av/at/arAliceAvatar"), b"avatar-bytes")
		.map_err(|e| err!("{e}"))?;
	write(export_dir.join("export.json"), export().to_string()).map_err(|e| err!("{e}"))?;

	let mut args = Args::default_test(&["fresh", "cleanup"]);
	args.maintenance = true;
	args.option
		.push(format!("database_path={db_path:?}"));

	let runtime = Runtime::new(Some(&args))?;
	let server = Server::new(Some(&args), Some(&runtime))?;

	let result: Result = runtime.block_on(async {
		let services = async_start(&server).await?;

		init(&services.admin);

		let outcome = exercise(&services, &export_dir.join("export.json")).await;

		fini(&services.admin);
		server.server.shutdown()?;
		drop(services);

		async_run(&server).await?;
		async_stop(&server).await?;

		outcome
	});

	drop(runtime);

	result
}

async fn exercise(services: &Services, export_path: &std::path::Path) -> Result {
	let command = format!("users import-synapse {}", export_path.display());
	let output = match services
		.admin
		.command_in_place(command.clone(), None)
		.await
	{
		| Ok(Some(output)) => output.as_str().to_owned(),
		| Ok(None) => return Err!("import produced no output"),
		| Err(output) => return Err!("import failed: {}", output.as_str()),
	};

	for expected in [
		"Imported 2 users (1 deactivated, 1 admins).",
		"Devices: 2; access tokens: 2; refresh tokens: 1; skipped tokens: 1.",
		"Device keys: 1; one-time keys: 2; fallback keys: 1; cross-signing users: 1.",
		"Key backups: 1 (1 sessions).",
		"Account data: 1; custom push rules: 1; filters: 1; media: 1.",
		"Warnings: 0",
	] {
		if !output.contains(expected) {
			return Err!("import output missing {expected:?}:\n{output}");
		}
	}

	if output.contains("syt_") || output.contains("syr_") || output.contains("$2b$") {
		return Err!("import output leaked a secret:\n{output}");
	}

	let alice = UserId::parse("@alice:localhost")?;
	let bob = UserId::parse("@bob:localhost")?;
	let device: &DeviceId = "ALICEPHONE".into();

	let (user_id, device_id, expires_at) = services
		.users
		.find_from_token(ACCESS_TOKEN)
		.await?;
	check(user_id == alice && device_id == device && expires_at.is_none(), "access token")?;

	check(
		services
			.users
			.find_from_token(EXPIRED_TOKEN)
			.await
			.is_err(),
		"expired token skipped",
	)?;

	let (_, tablet, _) = services
		.users
		.find_from_token(REFRESHABLE_TOKEN)
		.await?;
	check(tablet == "ALICETABLET", "refreshable token device")?;

	let refresh = services
		.users
		.classify_refresh_token(REFRESH_TOKEN)
		.await;
	check(
		matches!(refresh, RefreshToken::Current { ref device_id, .. } if device_id == "ALICETABLET"),
		"refresh token current",
	)?;

	let password_hash = services.users.password_hash(&alice).await?;
	check(password_hash == PASSWORD_HASH, "password hash kept")?;
	check(hash::verify_password(PASSWORD, &password_hash).is_ok(), "bcrypt verifies")?;
	check(services.users.is_deactivated(&bob).await?, "bob deactivated")?;
	check(!services.users.is_deactivated(&alice).await?, "alice active")?;
	check(services.admin.user_is_admin(&alice).await, "alice admin")?;

	check(
		services
			.profile
			.displayname(&alice)
			.await
			.ok()
			.as_deref()
			== Some("Alice"),
		"displayname",
	)?;

	services
		.users
		.get_device_keys(&alice, device)
		.await?;

	let otks = services
		.users
		.count_one_time_keys(&alice, device)
		.await;
	check(
		otks.get(&OneTimeKeyAlgorithm::SignedCurve25519) == Some(&UInt::from(2_u32)),
		"one-time keys",
	)?;

	let allow_all = |_: &UserId| true;
	let master = services
		.users
		.get_master_key(None, &alice, &allow_all)
		.await?;
	let master: Value = master.deserialize_as()?;
	check(
		master["signatures"]["@alice:localhost"]["ed25519:ALICEPHONE"] == "device-signs-master",
		"master key carries merged device signature",
	)?;

	check(
		services
			.key_backups
			.get_latest_backup_version(&alice)
			.await?
			== "3",
		"backup version kept",
	)?;
	check(services.key_backups.count_keys(&alice, "3").await == 1, "backup sessions")?;

	let room_id = RoomId::parse("!room:localhost")?;
	services
		.key_backups
		.get_session(&alice, "3", &room_id, "session1")
		.await?;

	let direct: Value = services
		.account_data
		.get_global(&alice, GlobalAccountDataEventType::Direct)
		.await?;
	check(direct["content"]["@bob:localhost"][0] == "!dm:localhost", "m.direct")?;

	let push_rules: PushRulesEvent = services
		.account_data
		.get_global(&alice, GlobalAccountDataEventType::PushRules)
		.await?;
	let global = push_rules.content.global;
	check(
		global
			.get(RuleKind::Room, "!muted:localhost")
			.is_some(),
		"room push rule",
	)?;
	check(
		global
			.get(RuleKind::Override, ".m.rule.master")
			.is_some_and(AnyPushRuleRef::enabled),
		"master rule enabled",
	)?;

	services.users.get_filter(&alice, "1").await?;

	let media = services
		.media
		.get(
			&Mxc {
				server_name: alice.server_name(),
				media_id: "avatarAliceAvatar",
			},
			None,
		)
		.await?;
	check(media.content == b"avatar-bytes", "media content")?;

	// A second run must refuse rather than duplicate or overwrite.
	check(
		services
			.admin
			.command_in_place(command, None)
			.await
			.is_err(),
		"re-import refused",
	)?;

	let preview = admin_output(services, "users purge-deactivated").await?;
	check(
		preview.contains("1 deactivated users can be purged, 0 skipped"),
		"purge preview",
	)?;
	check(services.users.exists(&bob).await, "preview keeps bob")?;

	let purged = admin_output(services, "users purge-deactivated --confirm").await?;
	check(purged.contains("Purged 1 deactivated users"), "purge output")?;
	check(!services.users.exists(&bob).await, "bob purged")?;
	check(
		services
			.account_data
			.get_raw(None, &bob, "m.push_rules")
			.await
			.is_err(),
		"bob push rules purged",
	)?;
	check(services.users.is_active(&alice).await, "alice kept")?;
	services.users.get_filter(&alice, "1").await?;

	check(
		admin_output(services, "users purge-deactivated")
			.await?
			.contains("0 deactivated users can be purged"),
		"purge is idempotent",
	)
}

async fn admin_output(services: &Services, command: &str) -> Result<String> {
	match services
		.admin
		.command_in_place(command.to_owned(), None)
		.await
	{
		| Ok(Some(output)) => Ok(output.as_str().to_owned()),
		| Ok(None) => Err!("{command} produced no output"),
		| Err(output) => Err!("{command} failed: {}", output.as_str()),
	}
}

fn check(ok: bool, what: &str) -> Result {
	if ok { Ok(()) } else { Err!("check failed: {what}") }
}

fn devices(alice: &str) -> Value {
	let now_ms = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("time")
		.as_millis();
	let past_ms = u64::try_from(now_ms)
		.expect("ms")
		.saturating_sub(60_000);

	json!([
		{
			"device_id": "ALICEPHONE",
			"display_name": "FluffyChat Android",
			"last_seen_ip": "192.0.2.1",
			"access_tokens": [
				{ "token": ACCESS_TOKEN, "expires_at_ms": null, "refresh_token": null },
				{ "token": EXPIRED_TOKEN, "expires_at_ms": past_ms, "refresh_token": null },
			],
			"device_keys": {
				"user_id": alice,
				"device_id": "ALICEPHONE",
				"algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
				"keys": {
					"curve25519:ALICEPHONE": "wjLpTLRqbqBzLs63aYaEv2Boi6cFEbbM/sSRQ2oAKk4",
					"ed25519:ALICEPHONE": "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM",
				},
				"signatures": {
					alice: {
						"ed25519:ALICEPHONE": "device-self-signature",
						format!("ed25519:{SELF_SIGNING_KEY}"): "self-signing-signs-device",
					},
				},
			},
			"one_time_keys": {
				"signed_curve25519:AAAAAQ": {
					"key": "zKbLg+NrIjpnagy+pIY6uPL4ZwEG2v+8F9lmgsnlZzs",
					"signatures": { alice: { "ed25519:ALICEPHONE": "otk-signature-1" } },
				},
				"signed_curve25519:AAAAAg": {
					"key": "Wb4tTkx/qa6wkpHpPP3KzpSjDhNA7Ax8+Kh2d72emxE",
					"signatures": { alice: { "ed25519:ALICEPHONE": "otk-signature-2" } },
				},
			},
			"fallback_keys": {
				"signed_curve25519:AAAAAw": {
					"key": "VRTnFuXyuXAAWdrKDnqgk1EbcSoGs9t0bGmLFYC1tQ4",
					"fallback": true,
					"signatures": { alice: { "ed25519:ALICEPHONE": "fallback-signature" } },
				},
			},
		},
		{
			"device_id": "ALICETABLET",
			"display_name": "Element",
			"last_seen_ip": null,
			"access_tokens": [
				{
					"token": REFRESHABLE_TOKEN,
					"expires_at_ms": past_ms,
					"refresh_token": REFRESH_TOKEN,
				},
			],
		},
	])
}

fn export() -> Value {
	let alice = "@alice:localhost";
	json!({
		"server_name": "localhost",
		"users": [
			{
				"user_id": alice,
				"password_hash": PASSWORD_HASH,
				"admin": true,
				"displayname": "Alice",
				"avatar_url": "mxc://localhost/avatarAliceAvatar",
				"account_data": {
					"m.direct": { "@bob:localhost": ["!dm:localhost"] },
				},
				"push_rules": [
					{
						"kind": "room",
						"rule_id": "!muted:localhost",
						"conditions": null,
						"actions": ["dont_notify"],
						"enabled": true,
					},
				],
				"push_rules_enabled": [
					{ "kind": "override", "rule_id": ".m.rule.master", "enabled": true },
				],
				"filters": {
					"1": { "room": { "state": { "lazy_load_members": true } } },
				},
				"devices": devices(alice),
				"cross_signing": {
					"master": {
						"user_id": alice,
						"usage": ["master"],
						"keys": { format!("ed25519:{MASTER_KEY}"): MASTER_KEY },
						"signatures": { alice: { "ed25519:ALICEPHONE": "device-signs-master" } },
					},
					"self_signing": {
						"user_id": alice,
						"usage": ["self_signing"],
						"keys": { format!("ed25519:{SELF_SIGNING_KEY}"): SELF_SIGNING_KEY },
						"signatures": { alice: { format!("ed25519:{MASTER_KEY}"): "master-signs-ssk" } },
					},
					"user_signing": {
						"user_id": alice,
						"usage": ["user_signing"],
						"keys": { format!("ed25519:{USER_SIGNING_KEY}"): USER_SIGNING_KEY },
						"signatures": { alice: { format!("ed25519:{MASTER_KEY}"): "master-signs-usk" } },
					},
				},
				"backups": [
					{
						"version": "3",
						"algorithm": {
							"algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
							"auth_data": {
								"public_key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo",
								"signatures": {},
							},
						},
						"sessions": [
							{
								"room_id": "!room:localhost",
								"session_id": "session1",
								"data": {
									"first_message_index": 0,
									"forwarded_count": 0,
									"is_verified": true,
									"session_data": {
										"ephemeral": "eph",
										"ciphertext": "cipher",
										"mac": "mac",
									},
								},
							},
						],
					},
				],
			},
			{
				"user_id": "@bob:localhost",
				"password_hash": PASSWORD_HASH,
				"deactivated": true,
				"displayname": null,
				"avatar_url": null,
			},
		],
		"media": [
			{
				"media_id": "avatarAliceAvatar",
				"user_id": alice,
				"content_type": "image/png",
				"upload_name": "avatar.png",
				"file": "local_content/av/at/arAliceAvatar",
			},
		],
	})
}
