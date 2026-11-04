use std::{collections::HashSet, sync::Arc};

use futures::{FutureExt, StreamExt};
use ruma::{
	OwnedRoomAliasId, OwnedRoomId, OwnedUserId, RoomId, UserId,
	events::{StateEventType, space::child::SpaceChildEventContent},
};
use serde::{Deserialize, Serialize};
use tuwunel_core::{
	Result, debug, err, matrix::PduCount, pdu::PduBuilder, result::LogErr, trace,
	utils::{
		future::BoolExt,
		stream::ReadyExt,
	},
	warn,
};

use crate::rooms::timeline::RoomMutexGuard;

pub struct Service {
	services: Arc<crate::services::OnceServices>,
}

/// Records local-user eviction results and aliases targeted for removal.
///
/// Its serialized layout matches Synapse's `ShutdownRoom`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShutdownRoom {
	pub kicked_users: Vec<OwnedUserId>,
	pub failed_to_kick_users: Vec<OwnedUserId>,
	pub local_aliases: Vec<OwnedRoomAliasId>,
	pub new_room_id: Option<OwnedRoomId>,
}

impl crate::Service for Service {
	fn build(args: &crate::Args<'_>) -> Result<Arc<Self>> {
		Ok(Arc::new(Self { services: args.services.clone() }))
	}

	fn name(&self) -> &str { crate::service::make_name(std::module_path!()) }
}

impl Service {
	pub async fn delete_if_empty_local(&self, room_id: &RoomId, state_lock: RoomMutexGuard) {
		debug_assert!(
			self.services.config.delete_rooms_after_leave,
			"Caller must checking if delete_rooms_after_leave configured."
		);

		let has_local_users = self
			.services
			.state_cache
			.local_users_in_room(room_id)
			.boxed()
			.into_future()
			.map(|(next, ..)| next.as_ref().is_some());

		let has_local_invites = self
			.services
			.state_cache
			.local_users_invited_to_room(room_id)
			.boxed()
			.into_future()
			.map(|(next, ..)| next.as_ref().is_some());

		if has_local_users.or(has_local_invites).await {
			trace!(?room_id, "Not deleting with local joined or invited");
			return;
		}

		debug!(?room_id, "Preparing to delete room...");

		self.services
			.delete
			.delete_room(room_id, false, state_lock)
			.boxed()
			.await
			.expect("unhandled error during room deletion");
	}

	pub async fn delete_room(
		&self,
		room_id: &RoomId,
		force: bool,
		state_lock: RoomMutexGuard,
	) -> Result<ShutdownRoom> {
		self.delete_room_as(room_id, force, None, state_lock)
			.await
	}

	/// Same as [`Self::delete_room`], but when `deleter` is set, also tries to
	/// clear `m.space.child` links from parent spaces before shutting the room
	/// down (best-effort; failures are logged and ignored).
	pub async fn delete_room_as(
		&self,
		room_id: &RoomId,
		force: bool,
		deleter: Option<&UserId>,
		state_lock: RoomMutexGuard,
	) -> Result<ShutdownRoom> {
		if let Some(deleter) = deleter {
			self.unlink_from_parent_spaces(room_id, deleter)
				.await;
		}

		let summary = self.shutdown_room(room_id, &state_lock).await;

		self.purge_room(room_id, force, &state_lock).await;

		self.services.spaces.cache_evict(room_id);

		debug!(?room_id, "Successfully deleted room from our database");

		Ok(summary)
	}

	/// Evicts every local user, strips the room's local aliases, and
	/// unpublishes it from the directory, returning the shutdown summary. The
	/// admin delete runs this phase alone when `purge` is false.
	pub async fn shutdown_room(
		&self,
		room_id: &RoomId,
		state_lock: &RoomMutexGuard,
	) -> ShutdownRoom {
		debug!(?room_id, "Making all local users leave the room");

		let joined = self
			.services
			.state_cache
			.local_users_in_room(room_id)
			.map(ToOwned::to_owned)
			.collect::<Vec<_>>()
			.await;

		let invited = self
			.services
			.state_cache
			.local_users_invited_to_room(room_id)
			.map(ToOwned::to_owned)
			.collect::<Vec<_>>()
			.await;

		let mut targets = HashSet::new();
		targets.extend(joined);
		targets.extend(invited);

		let (kicked_users, failed_to_kick_users) = futures::stream::iter(targets)
			.fold((Vec::new(), Vec::new()), async |(mut kicked, mut failed), user_id| {
				match self
					.services
					.membership
					.leave(&user_id, room_id, Some("Room Deleted".into()), true, state_lock)
					.await
				{
					| Ok(()) => {
						// `forget_forced_upon_leave` clears left-state immediately. Restore it
						// so clients still receive `rooms.leave` on the next /sync (including
						// the synthetic leave path after the room is purged).
						self.retain_leave_for_sync(&user_id, room_id)
							.await;
						kicked.push(user_id);
					},
					| Err(e) => {
						warn!(%e, "Failed to leave room");
						failed.push(user_id);
					},
				}

				(kicked, failed)
			})
			.await;

		debug!("Deleting all our room aliases for the room");
		let local_aliases = self
			.services
			.alias
			.local_aliases_for_room(room_id)
			.map(ToOwned::to_owned)
			.collect::<Vec<_>>()
			.await;

		for alias in &local_aliases {
			self.services
				.alias
				.remove_alias(alias)
				.await
				.log_err()
				.ok();
		}

		debug!("Removing/unpublishing room from our room directory");
		self.services.directory.set_not_public(room_id);

		ShutdownRoom {
			kicked_users,
			failed_to_kick_users,
			local_aliases,
			new_room_id: None,
		}
	}

	/// Keep a left-state row so /sync can notify the client the room went away,
	/// even when `forget_forced_upon_leave` already wiped it.
	async fn retain_leave_for_sync(&self, user_id: &UserId, room_id: &RoomId) {
		if self
			.services
			.state_cache
			.is_left(user_id, room_id)
			.await
		{
			return;
		}

		let count = self.services.globals.next_count();
		self.services
			.state_cache
			.mark_as_left(user_id, room_id, PduCount::Normal(*count));
	}

	/// Best-effort removal of this room from parent spaces' `m.space.child`
	/// state. Call **before** locking `room_id` when possible so parent locks
	/// do not nest under the child lock.
	pub async fn unlink_from_parent_spaces(&self, room_id: &RoomId, deleter: &UserId) {
		let parents = self
			.find_parent_spaces(room_id)
			.await;

		if parents.is_empty() {
			return;
		}

		debug!(
			?room_id,
			parents = parents.len(),
			"Unlinking deleted room from parent spaces"
		);

		let server_user = self.services.globals.server_user.as_ref();
		let actors: Vec<&UserId> = if deleter == server_user {
			vec![deleter]
		} else {
			vec![deleter, server_user]
		};

		for parent_id in parents {
			if parent_id == room_id {
				continue;
			}

			let mut cleared = false;
			for actor in &actors {
				match self
					.clear_space_child(&parent_id, room_id, actor)
					.await
				{
					| Ok(()) => {
						cleared = true;
						break;
					},
					| Err(e) => {
						trace!(
							%e,
							%parent_id,
							%room_id,
							actor = %actor,
							"m.space.child clear attempt failed"
						);
					},
				}
			}

			if !cleared {
				warn!(
					%parent_id,
					%room_id,
					"Could not clear m.space.child while deleting room"
				);
			}

			self.services.spaces.cache_evict(&parent_id);
		}
	}

	async fn find_parent_spaces(&self, room_id: &RoomId) -> Vec<OwnedRoomId> {
		let mut parents = HashSet::new();

		let from_parent_state: Vec<OwnedRoomId> = self
			.services
			.state_accessor
			.room_state_keys(room_id, &StateEventType::SpaceParent)
			.ready_filter_map(|key| OwnedRoomId::parse(key.as_str()).ok())
			.collect()
			.await;
		parents.extend(from_parent_state);

		let candidates: Vec<OwnedRoomId> = self
			.services
			.metadata
			.iter_ids()
			.map(ToOwned::to_owned)
			.ready_filter(|candidate| candidate.as_ref() != room_id)
			.collect()
			.await;

		for candidate in candidates {
			if self
				.services
				.state_accessor
				.room_state_get(&candidate, &StateEventType::SpaceChild, room_id.as_str())
				.await
				.is_ok()
			{
				parents.insert(candidate);
			}
		}

		parents.into_iter().collect()
	}

	async fn clear_space_child(
		&self,
		parent_id: &RoomId,
		child_id: &RoomId,
		deleter: &UserId,
	) -> Result {
		let has_child = self
			.services
			.state_accessor
			.room_state_get(parent_id, &StateEventType::SpaceChild, child_id.as_str())
			.await
			.is_ok();

		if !has_child {
			return Ok(());
		}

		if !self
			.services
			.state_cache
			.is_joined(deleter, parent_id)
			.await
		{
			return Err(err!(Request(Forbidden(
				"Deleter is not joined to parent space; cannot clear m.space.child"
			))));
		}

		let power_levels = self
			.services
			.state_accessor
			.get_power_levels(parent_id)
			.await
			.log_err()
			.ok();

		let can_send = match power_levels {
			| Some(pl) => pl.user_can_send_state(deleter, StateEventType::SpaceChild),
			| None => true,
		};

		if !can_send {
			return Err(err!(Request(Forbidden(
				"Deleter lacks power to clear m.space.child in parent space"
			))));
		}

		let state_lock = self.services.state.mutex.lock(parent_id).await;

		// Empty `via` removes the child per the Matrix spaces spec.
		self.services
			.timeline
			.build_and_append_pdu(
				PduBuilder::state(child_id.to_owned(), &SpaceChildEventContent::new(Vec::new())),
				deleter,
				parent_id,
				&state_lock,
			)
			.await?;

		Ok(())
	}

	/// Wipes the room's storage. `force` widens the erasure of local users'
	/// left-state (it is not Synapse's `force_purge`).
	async fn purge_room(&self, room_id: &RoomId, force: bool, state_lock: &RoomMutexGuard) {
		debug!("Deleting room's threads from database");
		self.services
			.threads
			.delete_all_rooms_threads(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting all the room's search token IDs from our database");
		self.services
			.search
			.delete_all_search_tokenids_for_room(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting all room's forward extremities from our database");
		self.services
			.state
			.delete_all_rooms_forward_extremities(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting all the room's event (PDU) references");
		self.services
			.pdu_metadata
			.delete_all_referenced_for_room(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting all the room's typed relation index entries");
		self.services
			.pdu_metadata
			.delete_all_relatesto_typed_for_room(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting all the room's member counts");
		self.services
			.state_cache
			.delete_room_join_counts(room_id, force)
			.await
			.log_err()
			.ok();

		debug!("Deleting all the room's private read receipts");
		self.services
			.read_receipt
			.delete_all_read_receipts(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting the room's last notifications read.");
		self.services
			.pusher
			.delete_room_notification_read(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting room state hash from our database");
		self.services
			.state
			.delete_room_shortstatehash(room_id, state_lock)
			.log_err()
			.ok();

		debug!("Deleting PDUs");
		self.services
			.timeline
			.delete_pdus(room_id)
			.await
			.log_err()
			.ok();

		debug!("Deleting internal room ID from our database");
		self.services
			.short
			.delete_shortroomid(room_id)
			.await
			.log_err()
			.ok();
	}
}
