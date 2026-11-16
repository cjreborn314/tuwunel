#!/usr/bin/env python3
"""Export Synapse accounts and sessions for `users import-synapse`.

Run inside the Synapse container so the database settings and media store are
available, with Synapse stopped so no token rotates after the export:

    docker exec -i matrix-synapse python - /data/homeserver.yaml \
        < synapse-export.py > export.json

The JSON written to stdout contains access tokens and password hashes; keep it
private and delete it after the import. Only counts are written to stderr.
Media files are referenced relative to the export file as local_content/...;
copy the media store's local_content directory next to export.json.

Deactivated users and their media are left out so their IDs do not exist on
Tuwunel; set EXPORT_DEACTIVATED=1 to export them as deactivated accounts.
"""

import json
import os
import sys
from collections import defaultdict

import psycopg2
import yaml

PUSH_RULE_PREFIX = "global/"


def connect(config):
    database = config["database"]
    if database.get("name") not in ("psycopg2", "postgres", "postgresql"):
        sys.exit(f"unsupported database engine {database.get('name')!r}")

    args = {
        key: value
        for key, value in database.get("args", {}).items()
        if key in ("user", "password", "database", "dbname", "host", "port")
    }
    return psycopg2.connect(**args)


def rows(cursor, query, *params):
    cursor.execute(query, params)
    names = [column.name for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def full_user_id(user_id, server_name):
    return user_id if user_id.startswith("@") else f"@{user_id}:{server_name}"


def add_signature(key, signer, key_id, signature):
    key.setdefault("signatures", {}).setdefault(signer, {}).setdefault(key_id, signature)


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "/data/homeserver.yaml"
    with open(config_path) as config_file:
        config = yaml.safe_load(config_file)

    server_name = config["server_name"]
    media_store = config.get("media_store_path", "/data/media_store")
    connection = connect(config)
    connection.set_session(readonly=True)
    cursor = connection.cursor()

    include_deactivated = os.environ.get("EXPORT_DEACTIVATED") == "1"
    dropped = set()
    users = {}
    for row in rows(
        cursor,
        """SELECT name, password_hash, admin, deactivated, locked, suspended
           FROM users WHERE appservice_id IS NULL AND COALESCE(is_guest, 0) = 0""",
    ):
        if row["deactivated"] and not include_deactivated:
            dropped.add(row["name"])
            continue
        users[row["name"]] = {
            "user_id": row["name"],
            "password_hash": row["password_hash"],
            "admin": bool(row["admin"]),
            "deactivated": bool(row["deactivated"]),
            "locked": bool(row["locked"]),
            "suspended": bool(row["suspended"]),
            "displayname": None,
            "avatar_url": None,
            "account_data": {},
            "push_rules": [],
            "push_rules_enabled": [],
            "filters": {},
            "devices": [],
            "cross_signing": {},
            "backups": [],
        }

    for row in rows(cursor, "SELECT user_id, full_user_id, displayname, avatar_url FROM profiles"):
        user = users.get(row["full_user_id"] or full_user_id(row["user_id"], server_name))
        if user:
            user["displayname"] = row["displayname"]
            user["avatar_url"] = row["avatar_url"] or None

    for row in rows(cursor, "SELECT user_id, account_data_type, content FROM account_data"):
        user = users.get(row["user_id"])
        if user and row["account_data_type"] != "m.push_rules":
            user["account_data"][row["account_data_type"]] = json.loads(row["content"])

    enabled = {
        (row["user_name"], row["rule_id"]): bool(row["enabled"])
        for row in rows(cursor, "SELECT user_name, rule_id, enabled FROM push_rules_enable")
    }
    custom_rules = set()
    for row in rows(
        cursor,
        """SELECT user_name, rule_id, conditions, actions FROM push_rules
           ORDER BY user_name, priority_class DESC, priority DESC""",
    ):
        user = users.get(row["user_name"])
        if not user or not row["rule_id"].startswith(PUSH_RULE_PREFIX):
            continue

        kind, _, rule_id = row["rule_id"][len(PUSH_RULE_PREFIX):].partition("/")
        if rule_id.startswith("."):
            print(f"skipping action override of base rule {kind}/{rule_id}", file=sys.stderr)
            continue

        custom_rules.add((row["user_name"], row["rule_id"]))
        user["push_rules"].append({
            "kind": kind,
            "rule_id": rule_id,
            "conditions": json.loads(row["conditions"] or "null"),
            "actions": json.loads(row["actions"] or "[]"),
            "enabled": enabled.get((row["user_name"], row["rule_id"]), True),
        })

    for (user_name, full_rule_id), is_enabled in enabled.items():
        user = users.get(user_name)
        if not user or (user_name, full_rule_id) in custom_rules:
            continue
        if not full_rule_id.startswith(PUSH_RULE_PREFIX):
            continue

        kind, _, rule_id = full_rule_id[len(PUSH_RULE_PREFIX):].partition("/")
        user["push_rules_enabled"].append({"kind": kind, "rule_id": rule_id, "enabled": is_enabled})

    for row in rows(cursor, "SELECT user_id, full_user_id, filter_id, filter_json FROM user_filters"):
        user = users.get(row["full_user_id"] or full_user_id(row["user_id"], server_name))
        if user:
            user["filters"][str(row["filter_id"])] = json.loads(bytes(row["filter_json"]))

    signatures = defaultdict(list)
    for row in rows(
        cursor,
        "SELECT user_id, key_id, target_user_id, target_device_id, signature "
        "FROM e2e_cross_signing_signatures",
    ):
        signatures[(row["target_user_id"], row["target_device_id"])].append(row)

    def merge_signatures(key, target_user_id, target_id):
        for signature in signatures.get((target_user_id, target_id), ()):
            add_signature(key, signature["user_id"], signature["key_id"], signature["signature"])
        return key

    devices = {}
    for row in rows(
        cursor,
        "SELECT user_id, device_id, display_name, ip FROM devices WHERE NOT COALESCE(hidden, false)",
    ):
        if row["user_id"] in users:
            devices[(row["user_id"], row["device_id"])] = {
                "device_id": row["device_id"],
                "display_name": row["display_name"],
                "last_seen_ip": row["ip"],
                "access_tokens": [],
                "device_keys": None,
                "one_time_keys": {},
                "fallback_keys": {},
            }

    for row in rows(
        cursor,
        """SELECT a.user_id, a.device_id, a.token, a.valid_until_ms, r.token AS refresh_token
           FROM access_tokens a LEFT JOIN refresh_tokens r ON r.id = a.refresh_token_id
           WHERE a.puppets_user_id IS NULL AND a.device_id IS NOT NULL
           ORDER BY a.id""",
    ):
        device = devices.get((row["user_id"], row["device_id"]))
        if device:
            device["access_tokens"].append({
                "token": row["token"],
                "expires_at_ms": row["valid_until_ms"],
                "refresh_token": row["refresh_token"],
            })

    for row in rows(cursor, "SELECT user_id, device_id, key_json FROM e2e_device_keys_json"):
        device = devices.get((row["user_id"], row["device_id"]))
        if device:
            key = json.loads(row["key_json"])
            device["device_keys"] = merge_signatures(key, row["user_id"], row["device_id"])

    for row in rows(
        cursor, "SELECT user_id, device_id, algorithm, key_id, key_json FROM e2e_one_time_keys_json"
    ):
        device = devices.get((row["user_id"], row["device_id"]))
        if device:
            key_id = f"{row['algorithm']}:{row['key_id']}"
            device["one_time_keys"][key_id] = json.loads(row["key_json"])

    for row in rows(
        cursor, "SELECT user_id, device_id, algorithm, key_id, key_json FROM e2e_fallback_keys_json"
    ):
        device = devices.get((row["user_id"], row["device_id"]))
        if device:
            key_id = f"{row['algorithm']}:{row['key_id']}"
            device["fallback_keys"][key_id] = json.loads(row["key_json"])

    for (user_id, _), device in devices.items():
        users[user_id]["devices"].append(device)

    for row in rows(
        cursor,
        """SELECT DISTINCT ON (user_id, keytype) user_id, keytype, keydata
           FROM e2e_cross_signing_keys ORDER BY user_id, keytype, stream_id DESC""",
    ):
        user = users.get(row["user_id"])
        if not user:
            continue

        key = json.loads(row["keydata"])
        public_key = next(iter(key.get("keys", {}).values()), None)
        user["cross_signing"][row["keytype"]] = merge_signatures(key, row["user_id"], public_key)

    sessions = defaultdict(list)
    for row in rows(
        cursor,
        """SELECT k.user_id, k.version, k.room_id, k.session_id, k.first_message_index,
                  k.forwarded_count, k.is_verified, k.session_data
           FROM e2e_room_keys k JOIN e2e_room_keys_versions v
             ON v.user_id = k.user_id AND v.version = k.version AND v.deleted = 0""",
    ):
        sessions[(row["user_id"], row["version"])].append({
            "room_id": row["room_id"],
            "session_id": row["session_id"],
            "data": {
                "first_message_index": row["first_message_index"],
                "forwarded_count": row["forwarded_count"],
                "is_verified": bool(row["is_verified"]),
                "session_data": json.loads(row["session_data"]),
            },
        })

    for row in rows(
        cursor,
        """SELECT user_id, version, algorithm, auth_data FROM e2e_room_keys_versions
           WHERE deleted = 0 ORDER BY user_id, version""",
    ):
        user = users.get(row["user_id"])
        if user:
            user["backups"].append({
                "version": str(row["version"]),
                "algorithm": {
                    "algorithm": row["algorithm"],
                    "auth_data": json.loads(row["auth_data"]),
                },
                "sessions": sessions.get((row["user_id"], row["version"]), []),
            })

    media = []
    missing_media = 0
    for row in rows(
        cursor,
        """SELECT media_id, media_type, upload_name, user_id FROM local_media_repository
           WHERE quarantined_by IS NULL AND url_cache IS NULL""",
    ):
        if row["user_id"] in dropped:
            continue
        media_id = row["media_id"]
        relative = os.path.join("local_content", media_id[0:2], media_id[2:4], media_id[4:])
        if not os.path.isfile(os.path.join(media_store, relative)):
            missing_media += 1
            continue

        media.append({
            "media_id": media_id,
            "user_id": row["user_id"] if row["user_id"] in users else None,
            "content_type": row["media_type"],
            "upload_name": row["upload_name"],
            "file": relative,
        })

    exported = list(users.values())
    json.dump({"server_name": server_name, "users": exported, "media": media}, sys.stdout)

    all_devices = [device for user in exported for device in user["devices"]]
    counts = {
        "users": len(exported),
        "deactivated": sum(user["deactivated"] for user in exported),
        "deactivated_dropped": len(dropped),
        "admins": sum(user["admin"] and not user["deactivated"] for user in exported),
        "devices": len(all_devices),
        "access_tokens": sum(len(device["access_tokens"]) for device in all_devices),
        "refresh_tokens": sum(
            token["refresh_token"] is not None
            for device in all_devices
            for token in device["access_tokens"]
        ),
        "device_keys": sum(device["device_keys"] is not None for device in all_devices),
        "one_time_keys": sum(len(device["one_time_keys"]) for device in all_devices),
        "fallback_keys": sum(len(device["fallback_keys"]) for device in all_devices),
        "cross_signing_users": sum("master" in user["cross_signing"] for user in exported),
        "backups": sum(len(user["backups"]) for user in exported),
        "backup_sessions": sum(
            len(backup["sessions"]) for user in exported for backup in user["backups"]
        ),
        "account_data": sum(len(user["account_data"]) for user in exported),
        "push_rules": sum(len(user["push_rules"]) for user in exported),
        "filters": sum(len(user["filters"]) for user in exported),
        "media": len(media),
        "missing_media": missing_media,
    }
    print(json.dumps(counts), file=sys.stderr)


if __name__ == "__main__":
    main()
