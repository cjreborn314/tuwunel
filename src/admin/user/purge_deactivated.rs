use std::pin::pin;

use futures::{Stream, StreamExt};
use ruma::OwnedUserId;
use tuwunel_core::{Result, warn};

use crate::admin_command;

#[admin_command]
pub(super) async fn purge_deactivated(&self, confirm: bool) -> Result {
	let services = self.services;
	let users: Vec<OwnedUserId> = services
		.users
		.stream()
		.map(ToOwned::to_owned)
		.collect()
		.await;

	let mut eligible = Vec::new();
	let mut skipped = 0_usize;
	for user_id in users {
		if user_id == services.globals.server_user
			|| !services.globals.user_is_local(&user_id)
			|| !services
				.users
				.is_deactivated(&user_id)
				.await
				.unwrap_or(false)
		{
			continue;
		}

		let state_cache = &services.state_cache;
		let has_devices = not_empty(services.users.all_device_ids(&user_id)).await;
		let has_rooms = not_empty(state_cache.rooms_joined(&user_id)).await
			|| not_empty(state_cache.rooms_invited(&user_id)).await
			|| not_empty(state_cache.rooms_knocked(&user_id)).await
			|| not_empty(state_cache.rooms_left(&user_id)).await;
		if has_devices || has_rooms || services.admin.user_is_admin(&user_id).await {
			warn!(%user_id, has_devices, has_rooms, "Not purging deactivated user");
			skipped = skipped.saturating_add(1);
			continue;
		}

		eligible.push(user_id);
	}

	if !confirm {
		return write!(
			self,
			"{} deactivated users can be purged, {skipped} skipped (see server log). Run again \
			 with --confirm to delete them.",
			eligible.len()
		)
		.await;
	}

	let mut media = 0_usize;
	for user_id in &eligible {
		media = media.saturating_add(
			services
				.media
				.delete_from_user(user_id)
				.await
				.unwrap_or(0),
		);

		let pushkeys: Vec<String> = services
			.pusher
			.get_pushkeys(user_id)
			.map(ToOwned::to_owned)
			.collect()
			.await;
		for pushkey in pushkeys {
			services
				.pusher
				.delete_pusher(user_id, &pushkey)
				.await;
		}

		services
			.key_backups
			.delete_all_backups(user_id)
			.await;
		services.presence.remove_presence(user_id).await;
		services
			.account_data
			.erase_user(user_id, None)
			.await;
		services.profile.clear_profile_keys(user_id).await;
		services.users.purge_account(user_id).await;
	}

	write!(
		self,
		"Purged {} deactivated users and {media} of their media, {skipped} skipped (see server \
		 log).",
		eligible.len()
	)
	.await
}

async fn not_empty<S: Stream>(stream: S) -> bool { pin!(stream).next().await.is_some() }
