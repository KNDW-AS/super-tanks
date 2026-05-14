"""
Tests for core/security/user_manager.py.

Covers the 5-level access system, PIN hashing, CRUD operations,
capability checks, curfew parsing, emergency keyword detection,
and the audit log. Each test uses the `user_db` fixture which
points USER_DB at a per-test tmp file and re-initialises the schema.
"""

from datetime import datetime, timezone

import pytest


# ── PIN hashing ────────────────────────────────────────────────────────────

class TestPinHash:
    def test_hash_is_deterministic(self, user_db):
        assert user_db._hash_pin("1234") == user_db._hash_pin("1234")

    def test_different_pins_yield_different_hashes(self, user_db):
        assert user_db._hash_pin("1234") != user_db._hash_pin("1235")

    def test_hash_length_is_32_hex_chars(self, user_db):
        h = user_db._hash_pin("anything")
        assert len(h) == 32
        int(h, 16)  # raises if not hex

    def test_hash_uses_install_salt(self, user_db):
        # Same PIN must not equal raw sha256(pin) — the salt is part of input.
        import hashlib
        raw = hashlib.sha256(b"1234").hexdigest()[:32]
        assert user_db._hash_pin("1234") != raw


# ── User CRUD ──────────────────────────────────────────────────────────────

class TestCreateUser:
    def test_creates_level_5_admin(self, user_db):
        res = user_db.create_user(name="William", pin="1234", level=5, created_by="system")
        assert res["success"] is True
        assert res["user_id"] == "william"

    def test_rejects_level_below_1(self, user_db):
        res = user_db.create_user(name="Test", pin="1", level=0, created_by="system")
        assert res["success"] is False

    def test_rejects_level_above_5(self, user_db):
        res = user_db.create_user(name="Test", pin="1", level=6, created_by="system")
        assert res["success"] is False

    def test_rejects_duplicate_user_id(self, user_db):
        user_db.create_user(name="William", pin="1234", level=5, created_by="system")
        res = user_db.create_user(name="William", pin="9999", level=5, created_by="system")
        assert res["success"] is False
        assert "exists" in res["error"]

    def test_user_id_is_lowercased_and_underscored(self, user_db):
        res = user_db.create_user(name="Big Bird", pin="1", level=3, created_by="system")
        assert res["user_id"] == "big_bird"

    def test_pin_is_never_stored_plaintext(self, user_db, tmp_path):
        user_db.create_user(name="William", pin="supersecret", level=5, created_by="system")
        raw = (tmp_path / "users.db").read_bytes()
        assert b"supersecret" not in raw

    def test_permitted_entities_serialized_as_json(self, user_db):
        user_db.create_user(name="Kid", pin="1", level=1, created_by="system",
                            permitted_entities=["light.kid_room", "switch.fan"])
        user = user_db.get_user("kid")
        assert user["permitted_entities"] == ["light.kid_room", "switch.fan"]


class TestGetUser:
    def test_returns_none_for_unknown(self, user_db):
        assert user_db.get_user("ghost") is None

    def test_omits_pin_hash(self, seed_admin):
        user = seed_admin.get_user("admin")
        assert "pin_hash" not in user

    def test_returns_level(self, seed_admin):
        assert seed_admin.get_user("admin")["level"] == 5


class TestListUsers:
    def test_empty_when_no_users(self, user_db):
        assert user_db.list_users() == []

    def test_sorted_by_level_descending(self, user_db):
        user_db.create_user(name="Low", pin="1", level=1, created_by="system")
        user_db.create_user(name="High", pin="1", level=5, created_by="system")
        user_db.create_user(name="Mid", pin="1", level=3, created_by="system")
        levels = [u["level"] for u in user_db.list_users()]
        assert levels == [5, 3, 1]


class TestUpdateUser:
    def test_updates_allowed_field(self, seed_admin):
        seed_admin.update_user("admin", actor="admin", name="Renamed")
        assert seed_admin.get_user("admin")["name"] == "Renamed"

    def test_ignores_disallowed_field(self, seed_admin):
        # pin_hash is not in allowed_fields — must be silently ignored.
        seed_admin.update_user("admin", actor="admin", pin_hash="ATTACKER_INJECTED")
        # Auth with original PIN must still succeed.
        assert seed_admin.authenticate("admin", "0000") is not None

    def test_level_clamped_to_valid_range(self, seed_admin):
        seed_admin.update_user("admin", actor="admin", level=99)
        assert seed_admin.get_user("admin")["level"] == 5
        seed_admin.update_user("admin", actor="admin", level=-3)
        assert seed_admin.get_user("admin")["level"] == 1

    def test_permitted_entities_list_serialized(self, seed_admin):
        seed_admin.update_user("admin", actor="admin",
                               permitted_entities=["light.a", "light.b"])
        assert seed_admin.get_user("admin")["permitted_entities"] == ["light.a", "light.b"]

    def test_unknown_user_returns_error(self, user_db):
        res = user_db.update_user("ghost", actor="admin", name="x")
        assert res["success"] is False


class TestDeleteUser:
    def test_cannot_delete_last_level_5(self, seed_admin):
        res = seed_admin.delete_user("admin", actor="admin")
        assert res["success"] is False
        assert "last Level 5" in res["error"]
        assert seed_admin.get_user("admin") is not None

    def test_can_delete_l5_when_another_l5_exists(self, seed_admin):
        seed_admin.create_user(name="Backup", pin="1", level=5, created_by="admin")
        res = seed_admin.delete_user("admin", actor="backup")
        assert res["success"] is True
        assert seed_admin.get_user("admin") is None

    def test_can_delete_non_l5(self, seed_admin):
        seed_admin.create_user(name="Kid", pin="1", level=1, created_by="admin")
        res = seed_admin.delete_user("kid", actor="admin")
        assert res["success"] is True

    def test_unknown_user_returns_error(self, seed_admin):
        res = seed_admin.delete_user("ghost", actor="admin")
        assert res["success"] is False


# ── Authentication ─────────────────────────────────────────────────────────

class TestAuthenticate:
    def test_correct_pin_returns_session(self, seed_admin):
        result = seed_admin.authenticate("admin", "0000")
        assert result is not None
        assert result["user_id"] == "admin"
        assert result["level"] == 5
        assert len(result["session_id"]) == 32  # token_hex(16) → 32 hex chars

    def test_wrong_pin_returns_none(self, seed_admin):
        assert seed_admin.authenticate("admin", "9999") is None

    def test_unknown_user_returns_none(self, seed_admin):
        assert seed_admin.authenticate("ghost", "0000") is None

    def test_updates_last_login(self, seed_admin):
        before = seed_admin.get_user("admin")["last_login"]
        assert before is None
        seed_admin.authenticate("admin", "0000")
        after = seed_admin.get_user("admin")["last_login"]
        assert after is not None
        # parseable as iso datetime
        datetime.fromisoformat(after)

    def test_session_ids_are_unique(self, seed_admin):
        a = seed_admin.authenticate("admin", "0000")["session_id"]
        b = seed_admin.authenticate("admin", "0000")["session_id"]
        assert a != b


# ── Capabilities ───────────────────────────────────────────────────────────

class TestHasCapability:
    @pytest.mark.parametrize("level,cap,expected", [
        (5, "system_delete", True),
        (4, "system_delete", False),
        (4, "user_management", True),
        (3, "smart_home", True),
        (3, "user_management", False),
        (2, "smart_home", False),         # L2 only has smart_home_permitted
        (2, "smart_home_permitted", True),
        (1, "chat_zeph", False),          # L1 is Aeris-only
        (1, "chat_aeris", True),
    ])
    def test_capability_matrix(self, user_db, level, cap, expected):
        user_db.create_user(name=f"U{level}", pin="1", level=level, created_by="system")
        assert user_db.has_capability(f"u{level}", cap) is expected

    def test_unknown_user_has_no_capability(self, user_db):
        assert user_db.has_capability("ghost", "chat_aeris") is False


# ── Curfew parsing ─────────────────────────────────────────────────────────

class TestParseCurfew:
    @pytest.mark.parametrize("raw,expected", [
        ("23:00", "23:00"),
        ("23", "23:00"),
        ("2300", "23:00"),
        ("11pm", "23:00"),
        ("11 pm", "23:00"),
        ("12am", "00:00"),
        ("12pm", "12:00"),
        ("9", "09:00"),
        ("09:30", "09:30"),
        ("9:5", "09:05"),
    ])
    def test_valid_formats(self, user_db, raw, expected):
        assert user_db._parse_curfew(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "abc", "25:00", "23:60", "9999"])
    def test_invalid_formats_return_none(self, user_db, raw):
        assert user_db._parse_curfew(raw) is None


class TestCheckCurfew:
    def test_no_curfew_means_allowed(self, seed_admin):
        assert seed_admin.check_curfew("admin")["allowed"] is True

    def test_unknown_user_is_allowed(self, seed_admin):
        # Aligns with current behaviour: missing user → no curfew rule applies.
        assert seed_admin.check_curfew("ghost")["allowed"] is True

    def test_outside_curfew_blocks(self, user_db, monkeypatch):
        user_db.create_user(name="Kid", pin="1", level=1, created_by="system",
                            curfew_time="22:00",
                            goodnight_message="God natt!")

        class FakeNow:
            @staticmethod
            def now(tz=None):
                return datetime(2024, 1, 1, 23, 30, 0)

            @staticmethod
            def fromisoformat(s):
                return datetime.fromisoformat(s)

        # The check uses naive datetime.now() inside check_curfew.
        monkeypatch.setattr(user_db, "datetime", FakeNow)
        result = user_db.check_curfew("kid")
        assert result["allowed"] is False
        assert result["goodnight"] == "God natt!"

    def test_within_curfew_allows(self, user_db, monkeypatch):
        user_db.create_user(name="Kid", pin="1", level=1, created_by="system",
                            curfew_time="22:00")

        class FakeNow:
            @staticmethod
            def now(tz=None):
                return datetime(2024, 1, 1, 15, 0, 0)

            @staticmethod
            def fromisoformat(s):
                return datetime.fromisoformat(s)

        monkeypatch.setattr(user_db, "datetime", FakeNow)
        assert user_db.check_curfew("kid")["allowed"] is True


# ── Emergency keyword detection ────────────────────────────────────────────

class TestCheckEmergency:
    @pytest.mark.parametrize("msg", [
        "There's a fire in the kitchen",
        "Help, I'm hurt!",
        "Det er brann!",
        "Trenger hjelp nå",
        "Call 112 now",
        "SOS",
    ])
    def test_detects_emergency_keywords(self, seed_admin, msg):
        assert seed_admin.check_emergency(msg, "admin") is True

    @pytest.mark.parametrize("msg", [
        "I need help with homework",
        "Trenger hjelp med lekser",
        "Could you help me understand this",
    ])
    def test_skips_homework_context(self, seed_admin, msg):
        assert seed_admin.check_emergency(msg, "admin") is False

    def test_no_emergency_in_normal_message(self, seed_admin):
        assert seed_admin.check_emergency("How is the weather", "admin") is False

    def test_emergency_override_off_disables_check(self, seed_admin):
        seed_admin.update_user("admin", actor="admin", emergency_override=0)
        assert seed_admin.check_emergency("FIRE!", "admin") is False

    def test_unknown_user_returns_false(self, seed_admin):
        assert seed_admin.check_emergency("FIRE!", "ghost") is False

    def test_case_insensitive(self, seed_admin):
        assert seed_admin.check_emergency("FIRE FIRE FIRE", "admin") is True


# ── Content filter ─────────────────────────────────────────────────────────

class TestContentFilter:
    def test_returns_empty_for_unknown_user(self, user_db):
        assert user_db.get_content_filter("ghost") == ""

    def test_returns_configured_filter(self, user_db):
        user_db.create_user(name="Kid", pin="1", level=1, created_by="system",
                            content_filter="no violence, no profanity")
        assert user_db.get_content_filter("kid") == "no violence, no profanity"


# ── Audit log ──────────────────────────────────────────────────────────────

class TestAudit:
    def test_create_user_writes_audit_entry(self, user_db):
        user_db.create_user(name="X", pin="1", level=3, created_by="system")
        entries = user_db.get_user_audit()
        assert any(e["action"] == "create_user" and e["target"] == "x" for e in entries)

    def test_delete_user_writes_audit_entry(self, seed_admin):
        seed_admin.create_user(name="Kid", pin="1", level=1, created_by="admin")
        seed_admin.delete_user("kid", actor="admin")
        entries = seed_admin.get_user_audit()
        assert any(e["action"] == "delete_user" and e["target"] == "kid" for e in entries)

    def test_update_user_writes_audit_entry(self, seed_admin):
        seed_admin.update_user("admin", actor="admin", name="Boss")
        entries = seed_admin.get_user_audit()
        assert any(e["action"] == "update_user" for e in entries)

    def test_limit_respected(self, user_db):
        for i in range(5):
            user_db.create_user(name=f"U{i}", pin="1", level=2, created_by="system")
        assert len(user_db.get_user_audit(limit=3)) == 3
