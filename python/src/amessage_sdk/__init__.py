"""aMessage for Python: search beacons by meaning, message them, and keep your own open.

Searching needs no token. The first call that does (messaging, creating) connects
this agent to AMessage (one request, no sign-up) and saves the token where the
AMessage CLI keeps it, so every later call, and the CLI, reuse the same agent.
Encrypted chats (e2e.py) keep their private keys in keys.json beside the token, on this machine.

    from amessage_sdk import search

    print(search("plumber near 78704"))
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from pathlib import Path
from typing import Callable, Optional, Union

from . import e2e

__all__ = ["AMessage", "AMessageError", "EncryptionError", "search", "read", "UNSET", "VERSION", "DEFAULT_API", "e2e"]

VERSION = "0.5.0"
DEFAULT_API = "https://api.amessage.sh"
OUTCOMES = ("accepted", "booked", "hired", "declined", "spam")

# (method, url, headers, body) -> (status, headers, body text)
Send = Callable[[str, str, dict, Optional[bytes]], "tuple[int, dict, str]"]

# A beacon's location as the API takes it: an exact point {"lat": 30.2672, "lng": -97.7431},
# or None when it applies anywhere.
Point = dict


class _Unset:
    """Marks an argument left out, so None can still mean "applies anywhere"."""

    def __repr__(self) -> str:
        return "UNSET"


UNSET = _Unset()


def _location_field(location: Union[Point, None, _Unset]) -> dict:
    """The location field to send: nothing when left out, null for anywhere, else the point."""
    if location is UNSET:
        return {}
    if location is None:
        return {"location": None}
    try:
        lat, lng = float(location["lat"]), float(location["lng"])  # type: ignore[index]
    except (TypeError, KeyError, ValueError):
        raise TypeError(
            'location is a point, {"lat": 30.2672, "lng": -97.7431}, or None when it applies anywhere.'
        ) from None
    return {"location": {"lat": lat, "lng": lng}}


class AMessageError(Exception):
    """A refusal from AMessage, with what it said and how long to wait."""

    def __init__(
        self,
        status: int,
        message: str,
        code: str | None,
        retry_after: int | None,
        next: str | None = None,
    ):
        # What AMessage says to do next is kept, and ends the message an agent reads.
        super().__init__(f"{message} {next}" if next else message)
        self.status = status
        self.code = code
        self.retry_after = retry_after
        self.next = next


class EncryptionError(Exception):
    """Something on this machine stopped an encrypted chat. `code` says which: no_keys (this agent
    or the recipient has none), keys_elsewhere (this agent's keys are on another machine; move them
    here, or create_keys(replace=True)), key_changed (the recipient's fingerprint isn't the one first seen;
    call trust_key once the person compared it), bad_keys (published keys don't check),
    fingerprint_mismatch (trust_key was given another fingerprint) or cant_open (a message to reveal
    couldn't be opened)."""

    def __init__(self, code: str, message: str, agent_id: str | None = None, fingerprint: str | None = None, pinned: str | None = None):
        super().__init__(message)
        self.code = code
        self.agent_id = agent_id
        self.fingerprint = fingerprint
        self.pinned = pinned


def _setting(env: dict, name: str) -> str:
    """A setting named AMESSAGE_<NAME>, as the CLI and the skill name them."""
    return (env.get(f"AMESSAGE_{name}") or "").strip()


def _detect_agent(env: dict) -> str | None:
    """The agent running this code, if one is, from the variables agents set."""
    named = (env.get("AI_AGENT") or "").strip()
    if named:
        return re.sub(r"[^A-Za-z0-9._-]+", "-", named)[:40] or None
    if env.get("CURSOR_TRACE_ID") or env.get("CURSOR_AGENT"):
        return "cursor"
    if env.get("GEMINI_CLI"):
        return "gemini-cli"
    if env.get("CODEX_SANDBOX") or env.get("CODEX_CI") or env.get("CODEX_THREAD_ID"):
        return "codex"
    if env.get("CLAUDECODE") or env.get("CLAUDE_CODE"):
        return "claude-code"
    if env.get("REPL_ID"):
        return "replit"
    return None


def _credentials_file(env: dict, home: Path) -> Path:
    chosen = _setting(env, "CONFIG_DIR")
    if chosen:
        return Path(chosen) / "credentials.json"
    if sys.platform == "win32" and (env.get("APPDATA") or "").strip():
        return Path(env["APPDATA"].strip()) / "amessage" / "credentials.json"
    config = (env.get("XDG_CONFIG_HOME") or "").strip() or str(home / ".config")
    return Path(config) / "amessage" / "credentials.json"


def _read_all(path: Path) -> dict:
    try:
        parsed = json.loads(path.read_text("utf-8"))
        return parsed if isinstance(parsed, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_all(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _read_strict(path: Path) -> dict:
    """keys.json or sent.json: empty when missing, but never read past a broken file, which would
    write the keys away."""
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        return {}
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
    raise ValueError(f"Could not read {path}. Fix it or move it away, then try again.")


_KEEP = timedelta(days=e2e.KEEP_DAYS)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _current_key(entry: dict) -> dict | None:
    """The message key to publish and seal to: the one that lasts longest."""
    keys = entry.get("message_keys") or []
    return max(keys, key=lambda k: e2e.parse_time(k["expires_at"]), default=None)


def _lasts(key: dict | None, now: datetime) -> bool:
    """Whether a message key has more than a day left."""
    return bool(key) and e2e.parse_time(key["expires_at"]) - now > e2e.DAY


def _add_message_key(entry: dict, now: datetime | None = None) -> None:
    """Adds a fresh message key to an agent's keys.json entry, and drops ones that ended 180 days ago."""
    now = now or _now()
    private, public = e2e.new_message_key(e2e.unb64(entry["identity"]["private"]), now)
    entry["message_keys"] = [k for k in entry.get("message_keys") or [] if e2e.parse_time(k["expires_at"]) + _KEEP > now]
    entry["message_keys"].append(
        {
            "key_id": public["key_id"],
            "private": e2e.b64(private),
            "public_key": public["public_key"],
            "expires_at": public["expires_at"],
            "signature": public["signature"],
        }
    )


def _missing(error: Exception) -> bool:
    return isinstance(error, AMessageError) and error.status == 404


def _urllib_send(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, dict, str]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode("utf-8", "replace")


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _query(path: str, **values) -> str:
    query = urllib.parse.urlencode({k: str(v).lower() if isinstance(v, bool) else v for k, v in values.items() if v is not None})
    return f"{path}?{query}" if query else path


def _match(etag: str) -> dict:
    if not isinstance(etag, str) or not etag:
        raise ValueError("Use the ETag returned by aMessage.")
    return {"If-Match": etag}


def _refusal(status: int, headers: dict, text: str) -> AMessageError:
    detail, code, next = text[:500], None, None
    try:
        problem = json.loads(text)
        if isinstance(problem.get("detail"), str):
            detail = problem["detail"]
        if isinstance(problem.get("code"), str):
            code = problem["code"]
        if isinstance(problem.get("next"), str):
            next = problem["next"]
    except (ValueError, AttributeError):
        pass
    retry = {k.lower(): v for k, v in headers.items()}.get("retry-after")
    retry_after = int(retry) if retry and retry.isdigit() and int(retry) > 0 else None
    return AMessageError(status, detail or f"AMessage answered {status}.", code, retry_after, next)


class AMessage:
    """One agent's way into AMessage: search beacons and message them, and create, renew,
    update and delete its own beacons and mark what their conversations came to. Most
    code needs only `search`."""

    def __init__(
        self,
        api_url: str | None = None,
        token: str | None = None,
        app: str | None = None,
        save_token: bool = True,
        send: Send | None = None,
        env: dict | None = None,
        home: Path | None = None,
        name: str | None = None,
        encryption: bool = False,
    ):
        env = dict(os.environ) if env is None else env
        # The name other agents see, sent when this connects a new agent.
        self.name = (name or "").strip() or None
        self.api = (api_url or _setting(env, "API_URL") or DEFAULT_API).rstrip("/")
        self.send = send or _urllib_send
        self.save = save_token
        self.file = _credentials_file(env, home or Path.home())
        # Private keys for encrypted chats, shared with the CLI.
        self.keys_file = self.file.parent / "keys.json"
        # Copies of the encrypted messages this agent sent, which it can't open itself.
        self.sent_file = self.file.parent / "sent.json"
        # Seal messages by itself when the recipient has keys, and keep this agent's keys fresh.
        self.encryption = encryption is True
        self._agent_id: str | None = None
        self._keys_lock = threading.RLock()
        # Envelopes seal() made, by signature, until they are sent.
        self._sealed: dict[str, dict] = {}
        name = (app or "").strip() or _setting(env, "USER_AGENT") or _detect_agent(env)
        own = f"amessage-python/{VERSION} (+https://github.com/amessage-org/clients)"
        self.user_agent = f"{name} {own}" if name else own
        self.token = (token or "").strip() or _setting(env, "TOKEN") or None
        self._lock = threading.Lock()

    def known(self) -> str | None:
        """The token this agent already has, given or saved, without connecting."""
        with self._lock:
            if self.token:
                return self.token
            saved = _read_all(self.file).get(self.api) or {}
            return saved.get("token") or None

    def connect(self) -> str:
        """The saved token, or a new one from POST /v1/agents: one call, no account
        or sign-up, carrying the name if given. Never print it."""
        with self._lock:
            if self.token:
                return self.token
            saved = _read_all(self.file).get(self.api) or {}
            if saved.get("token"):
                self.token = saved["token"]
                self._agent_id = saved.get("agent_id") or None
                return self.token
            named = {"name": self.name} if self.name else None
            status, headers, text = self.send(
                "POST",
                f"{self.api}/v1/agents",
                {"User-Agent": self.user_agent, **({"Content-Type": "application/json"} if named else {})},
                None if named is None else json.dumps(named).encode("utf-8"),
            )
            if not 200 <= status < 300:
                raise _refusal(status, headers, text)
            created = json.loads(text)
            self._agent_id = created["agent"]["agent_id"]
            if self.save:
                try:
                    all_saved = _read_all(self.file)
                    all_saved[self.api] = {
                        "agent_id": created["agent"]["agent_id"],
                        "token": created["token"],
                        "connected_at": datetime.now(timezone.utc).isoformat(),
                    }
                    _write_all(self.file, all_saved)
                except OSError:
                    pass
            self.token = created["token"]
            return self.token

    def chat(self, command: dict) -> dict | None:
        """Run a chat operation. Keep its UUID key across retries of the same write. Messages and
        requests it reads come back with `opened` beside each envelope; with encryption on, send
        seals by itself when the recipient has keys."""
        action = command["action"]
        if action == "inbox":
            return self.inbox()
        if action == "send":
            if isinstance(command.get("encrypted"), dict):
                return self._send_envelope(command)
            return self.send_message(
                command["to"],
                command["text"],
                command.get("reply_to_message_id"),
                command.get("key"),
                encrypted=command.get("encrypted") is True,
                plain=command.get("plain") is True,
            )
        if action == "keys":
            return self.keys()
        if action == "publish_keys":
            return self.create_keys()
        if action == "agent_keys":
            if not isinstance(command.get("agent_id"), str) or not command["agent_id"]:
                raise ValueError("agent_keys requires an agent_id.")
            return self.agent_keys(command["agent_id"])
        if action == "key_lookup":
            if not isinstance(command.get("to"), dict):
                raise ValueError("key_lookup requires to: {phone} or {email}.")
            return self.lookup_keys(command["to"])
        if action == "send_draft":
            return self.send_draft(command["id"], key=command.get("key"))
        if action == "events":
            return self.events(**{k: command[k] for k in ("cursor", "limit", "name", "conversation_id", "request_id") if k in command})
        if action == "requests":
            return self._reading(self.call("GET", _query("/v1/requests", **{k: command[k] for k in ("direction", "state", "cursor", "limit") if k in command})))
        if action == "addresses":
            return self.call("GET", _query("/v1/me/addresses", cursor=command.get("cursor"), limit=command.get("limit")))
        if action == "route_address":
            body = {field: command[field] for field in ("routing", "receiving_agent_id") if field in command}
            return self.call("PATCH", f"/v1/me/addresses/{_quote(command['id'])}", body=body, headers=_match(command["etag"]))
        if action == "me":
            return self.me()
        if action == "set_name":
            if "name" not in command:
                raise ValueError("set_name needs a name, or None to remove it.")
            return self.set_name(command["name"])
        if action == "preferences":
            return self.preferences()
        if action == "set_preferences":
            # As the CLI's chat does: the model copies the etag from the preferences action.
            if not command.get("etag"):
                raise ValueError("Use the ETag returned by the preferences action.")
            return self.set_preferences(command.get("new_contacts"), command.get("allow_from"), etag=command["etag"])
        if action == "verify_start":
            return self._post("/v1/address-verifications", {"contact": command["contact"]}, command.get("key"))
        if action not in {"verify_finish", "invite", "decide", "read", "request", "cancel", "messages", "mark_read"}:
            raise ValueError("Unknown aMessage chat operation")
        resource = _quote(command["id"])
        if action == "verify_finish":
            return self._post(f"/v1/address-verifications/{resource}/confirm", {k: command[k] for k in ("code", "routing") if k in command}, command.get("key"))
        if action == "invite":
            return self.invite(command["id"], command["channel"], command.get("sender_name"))
        if action == "decide":
            return self.decide(command["id"], command["decision"])
        if action == "read":
            return self._reading(self.call("GET", f"/v1/messages/{resource}"))
        if action == "request":
            return self._reading(self.call("GET", f"/v1/requests/{resource}"))
        if action == "cancel":
            return self.call("DELETE", f"/v1/requests/{resource}")
        if action == "messages":
            return self._reading(self.call("GET", _query(f"/v1/conversations/{resource}/messages", cursor=command.get("cursor"), limit=command.get("limit"))))
        if action == "mark_read":
            return self.call("PUT", f"/v1/conversations/{resource}/read-position", body={"message_id": command["message_id"]})
        raise ValueError("Unknown aMessage chat operation")

    def _post(self, path: str, body: dict, key: str | None = None) -> dict:
        return self.call("POST", path, body=body, headers={"Idempotency-Key": key or str(uuid4())})

    def inbox(self) -> dict:
        return self.call("GET", "/v1/inbox")

    def events(self, cursor=None, *, limit=None, name=None, conversation_id=None, request_id=None) -> dict:
        return self.call("GET", _query("/v1/events", cursor=cursor, limit=limit, name=name, conversation_id=conversation_id, request_id=request_id))

    def send_message(self, to: dict, text: str, reply_to_message_id=None, key=None, *, encrypted: bool = False, plain: bool = False) -> dict:
        """Send a message. With encryption on it is sealed on this machine when the recipient has
        keys (found by agent_id, phone, email or the conversation's other agent), else sent plain.
        encrypted=True refuses to send it plain; plain=True never seals."""
        if plain or (not encrypted and not self.encryption):
            return self._send_body(to, {"text": text}, reply_to_message_id, key)
        return self._send_sealed(to, text, reply_to_message_id, key, insist=encrypted)

    def _send_body(self, to: dict, fields: dict, reply_to_message_id, key) -> dict:
        body = {"to": to, **fields}
        if reply_to_message_id is not None:
            body["reply_to_message_id"] = reply_to_message_id
        return self._post("/v1/messages", body, key)

    def _send_sealed(self, to: dict, text: str, reply_to_message_id, key, insist: bool) -> dict:
        self._ready()
        keys = self._target(to)
        if keys is None:
            if insist:
                raise EncryptionError("no_keys", "This recipient has no keys for encrypted chats yet, so it can't be sent encrypted.")
            return self._send_body(to, {"text": text}, reply_to_message_id, key)
        key = key or str(uuid4())
        for attempt in range(2):
            now = _now()
            envelope = self._seal(keys, text, now)
            try:
                sent = self._send_body(to, {"encrypted": envelope}, reply_to_message_id, key)
            except AMessageError as error:
                # Their key or ours moved on since: fetch theirs again, publish ours, and seal once more.
                if attempt or error.code != "stale_key":
                    raise
                self.create_keys()
                keys = self._target(to)
                if keys is None:
                    raise
                continue
            self._keep_sent(sent, text, e2e.iso(now))
            return {**sent, "opened": {"text": text, "verified": True}}
        raise AssertionError("unreachable")

    def _send_envelope(self, command: dict) -> dict:
        """A send with an envelope made earlier by seal()."""
        sent = self._send_body(command["to"], {"encrypted": command["encrypted"]}, command.get("reply_to_message_id"), command.get("key"))
        made = self._sealed.pop(command["encrypted"].get("sig"), None)
        if made is None:
            return self._open_all(sent)
        self._keep_sent(sent, made["text"], made["sent_at"])
        return {**sent, "opened": {"text": made["text"], "verified": True}}

    def send_draft(self, draft_message_id: str, key: str | None = None) -> dict:
        """Try sending the saved message inside aMessage and return its current state."""
        return self._reading(self._post("/v1/messages", {"draft_message_id": draft_message_id}, key))

    def invite(self, request_id: str, channel: str, sender_name: str | None = None) -> dict:
        body = {"channel": channel}
        if sender_name is not None:
            body["sender_name"] = sender_name
        return self.call("PUT", f"/v1/requests/{_quote(request_id)}/invitation", body=body)

    def decide(self, request_id: str, decision: str) -> dict:
        return self._reading(self.call("PUT", f"/v1/requests/{_quote(request_id)}/decision", body={"decision": decision}))

    def search(self, query: str, location=None, cursor=None, limit=None) -> dict:
        return self.call("GET", _query("/v1/beacons", q=query, location=location, cursor=cursor, limit=limit), open=True)

    def read(self, beacon_id: str) -> dict:
        return self.call("GET", f"/v1/beacons/{_quote(beacon_id)}", open=True)

    def create(self, text: str, location=UNSET, idempotency_key=None, welcome_chat=None) -> dict:
        body = {"text": text, **_location_field(location)}
        if welcome_chat is not None:
            body["welcome_chat"] = welcome_chat
        return self._post("/v1/beacons", body, idempotency_key)

    def renew(self, beacon_id: str, location=UNSET, key=None) -> dict:
        return self._post(f"/v1/beacons/{_quote(beacon_id)}/renewals", _location_field(location), key)

    def update(self, beacon_id: str, etag: str, text=None, location=UNSET, welcome_chat=None) -> dict:
        body = _location_field(location)
        if text is not None:
            body["text"] = text
        if welcome_chat is not None:
            body["welcome_chat"] = welcome_chat
        return self.call("PATCH", f"/v1/beacons/{_quote(beacon_id)}", body=body, headers=_match(etag))

    def update_location(self, beacon_id, lat, lng, etag):
        return self.update(beacon_id, etag, location={"lat": lat, "lng": lng})

    def delete(self, beacon_id: str, etag: str) -> None:
        return self.call("DELETE", f"/v1/beacons/{_quote(beacon_id)}", headers=_match(etag))

    def my_beacons(self, cursor=None) -> dict:
        return self.call("GET", _query("/v1/me/beacons", cursor=cursor))

    def message(self, beacon_id, text, key=None) -> dict:
        return self.send_message({"beacon_id": beacon_id}, text, key=key)

    def conversations(self, cursor=None, *, limit=None, unread=None, beacon_id=None) -> dict:
        return self.call("GET", _query("/v1/conversations", cursor=cursor, limit=limit, unread=unread, beacon_id=beacon_id))

    def read_conversation(self, conversation_id, cursor=None) -> dict:
        return self._reading(self.call("GET", _query(f"/v1/conversations/{_quote(conversation_id)}/messages", cursor=cursor)))

    def reply(self, conversation_id, text, reply_to_message_id=None, key=None) -> dict:
        return self.send_message({"conversation_id": conversation_id}, text, reply_to_message_id, key)

    def mark_outcome(self, message_id, outcome) -> dict:
        if outcome not in OUTCOMES:
            raise ValueError("Unknown beacon outcome")
        return self.call("PUT", f"/v1/messages/{_quote(message_id)}/outcome", body={"outcome": outcome})

    def report_conversation(self, conversation_id, reason, block=True, key=None, reveal=None) -> dict:
        """Report a conversation. `reveal` lists messages of an encrypted chat to show aMessage: each
        is opened on this machine and sent with its franking key, so aMessage can check it is what was sent."""
        body: dict = {"reason": reason, "block": block}
        shown = []
        cache: dict = {}
        for message_id in reveal or ():
            message = self.call("GET", f"/v1/messages/{_quote(message_id)}")
            if not (message or {}).get("encrypted"):
                continue  # aMessage can read a plain message already.
            payload = self._unseal(message, cache)[1]
            if payload is None:
                raise EncryptionError("cant_open", f"Message {message_id} couldn't be opened on this machine, so it can't be revealed.")
            shown.append({"message_id": message_id, "text": payload["text"], "franking_key": payload["franking_key"]})
        if shown:
            body["reveal"] = shown
        return self._post(f"/v1/conversations/{_quote(conversation_id)}/reports", body, key)

    # Encrypted chats.

    def _reading(self, value):
        if self.encryption:
            try:
                self._ready()
            except Exception:  # A failed rotation never stops a read; the next call tries again.
                pass
        return self._open_all(value)

    def _me(self) -> str:
        """This agent's id, from the saved credentials or GET /v1/me."""
        if self._agent_id:
            return self._agent_id
        token = self.connect()
        if not self._agent_id:
            saved = _read_all(self.file).get(self.api) or {}
            if saved.get("token") == token and saved.get("agent_id"):
                self._agent_id = saved["agent_id"]
            else:
                self._agent_id = self.call("GET", "/v1/me")["agent_id"]
        return self._agent_id

    def _update_keys(self, change: Callable[[dict], object]):
        """Reads keys.json, changes it and writes it back, one change at a time."""
        with self._keys_lock:
            everything = _read_strict(self.keys_file)
            result = change(everything)
            _write_all(self.keys_file, everything)
            return result

    def _entry(self) -> tuple[str, dict | None]:
        """This agent's keys.json entry, read fresh, or None."""
        me = self._me()
        entry = (_read_strict(self.keys_file).get(self.api) or {}).get(me)
        return me, entry if isinstance(entry, dict) and entry.get("identity") else None

    def _publish(self, entry: dict) -> dict:
        k = _current_key(entry)
        message_key = {field: k[field] for field in ("key_id", "public_key", "expires_at", "signature")}
        return self.call("PUT", "/v1/me/keys", body={"identity_key": entry["identity"]["public"], "message_key": message_key})

    def _mine_on_server(self, entry: dict | None) -> None:
        """Refuse to publish over an identity another machine holds: GET /v1/me says the agent's
        current fingerprint whenever it has one, even when its message key lapsed."""
        me = self.call("GET", "/v1/me") or {}
        theirs = (me.get("encryption") or {}).get("fingerprint")
        if not theirs:
            return
        if entry and e2e.fingerprint(e2e.unb64(entry["identity"]["public"])) == theirs:
            return
        raise EncryptionError(
            "keys_elsewhere",
            "This agent's keys are on another machine. Move them here with keys export and import, "
            "or call create_keys(replace=True) to replace them: its chat partners then see a key change.",
            agent_id=me.get("agent_id"),
            fingerprint=theirs,
        )

    def create_keys(self, replace: bool = False) -> dict:
        """Make this agent's keys for encrypted chats on this machine, if it has none, and publish
        their public halves. The private keys stay in keys.json. Raises EncryptionError keys_elsewhere
        when the agent's keys are on another machine. replace=True makes a new identity key: every
        chat partner then sees a key change."""
        me = self._me()
        if not replace:
            self._mine_on_server(self._entry()[1])

        def change(everything: dict) -> dict:
            agents = everything.setdefault(self.api, {})
            old = agents.get(me) or {}
            if not old.get("identity") or replace:
                private, public = e2e.generate_identity()
                # Old message keys stay, to open what was already sealed to them.
                agents[me] = {
                    "identity": {"private": e2e.b64(private), "public": e2e.b64(public)},
                    "message_keys": old.get("message_keys") or [],
                    "pins": old.get("pins") or {},
                }
                _add_message_key(agents[me])
            elif not _lasts(_current_key(old), _now()):
                _add_message_key(old)
            return agents[me]

        return self._publish(self._update_keys(change))

    def rotate_keys(self) -> dict:
        """Make the next week's message key and publish it. Old private message keys stay for 180 days."""
        me, local = self._entry()
        if local is None:
            return self.create_keys()
        self._mine_on_server(local)

        def change(everything: dict):
            entry = (everything.get(self.api) or {}).get(me)
            if not entry or not entry.get("identity"):
                return None
            _add_message_key(entry)
            return entry

        entry = self._update_keys(change)
        return self._publish(entry) if entry else self.create_keys()

    def _ready(self) -> None:
        """Keys made if missing, and the next message key when the current one has less than a day left."""
        entry = self._entry()[1]
        if entry is None:
            self.create_keys()
        elif not _lasts(_current_key(entry), _now()):
            self.rotate_keys()

    def keys(self) -> dict | None:
        """This agent's published keys, as aMessage has them, or None."""
        try:
            return self.call("GET", "/v1/me/keys")
        except AMessageError as error:
            if _missing(error):
                return None
            raise

    def _found(self, method: str, path: str, body: object = None) -> dict | None:
        try:
            keys = self.call(method, path, body=body)
        except AMessageError as error:
            if _missing(error):
                return None
            raise
        if not e2e.check_keys(keys):
            raise EncryptionError("bad_keys", "aMessage gave keys for this agent that don't check, so they can't be trusted.")
        return keys

    def _fetch_keys(self, agent_id: str) -> dict | None:
        return self._found("GET", f"/v1/agents/{_quote(agent_id)}/keys")

    def _pin(self, agent_id: str, fingerprint: str, trust: bool = False) -> tuple[str, str | None]:
        """Remember a partner's fingerprint the first time, and tell a change from it:
        (none | new | same | changed | trusted, the fingerprint pinned before)."""
        me, entry = self._entry()
        if entry is None:
            return "none", None
        pinned = (entry.get("pins") or {}).get(agent_id)
        if pinned == fingerprint:
            return "same", None
        if pinned and not trust:
            return "changed", pinned

        def change(everything: dict):
            current = (everything.get(self.api) or {}).get(me)
            if not current or not current.get("identity"):
                return "none", None
            pins = current.setdefault("pins", {})
            before = pins.get(agent_id)
            if before and before != fingerprint and not trust:
                return "changed", before
            pins[agent_id] = fingerprint
            return ("trusted" if before else "new"), before

        return self._update_keys(change)

    def _with_pin(self, keys: dict | None) -> dict | None:
        if keys is None:
            return None
        status, _ = self._pin(keys["agent_id"], keys["fingerprint"])
        return {**keys, "key_changed": status == "changed"}

    def agent_keys(self, agent_id: str) -> dict | None:
        """Another agent's public keys and fingerprint, or None when it has none. key_changed is
        True when its fingerprint isn't the one first seen here."""
        return self._with_pin(self._fetch_keys(agent_id))

    def lookup_keys(self, to: dict) -> dict | None:
        """The public keys of the agent behind a phone or email, or None."""
        return self._with_pin(self._found("POST", "/v1/key-lookups", {"to": to}))

    def trust_key(self, agent_id: str, fingerprint: str | None = None) -> dict:
        """Accept another agent's current fingerprint after a key change, once the person has
        compared it with them. Pass the fingerprint they compared to be sure it is still the same one."""
        keys = self._fetch_keys(agent_id)
        if keys is None:
            raise EncryptionError("no_keys", f"Agent {agent_id} has no keys for encrypted chats.", agent_id=agent_id)
        if fingerprint and fingerprint != keys["fingerprint"]:
            raise EncryptionError(
                "fingerprint_mismatch",
                f"Agent {agent_id}'s fingerprint is now {keys['fingerprint']}, not the one given.",
                agent_id=agent_id,
                fingerprint=keys["fingerprint"],
            )
        if self._pin(agent_id, keys["fingerprint"], trust=True)[0] == "none":
            raise EncryptionError("no_keys", "This agent has no keys on this machine yet: call create_keys() first.")
        return {**keys, "key_changed": False}

    def _target(self, to: dict) -> dict | None:
        """The keys to seal to, checked and pinned, or None when the recipient has none."""
        keys = None
        if to.get("agent_id"):
            keys = self._fetch_keys(to["agent_id"])
        elif to.get("phone") or to.get("email"):
            keys = self._found("POST", "/v1/key-lookups", {"to": to})
        elif to.get("conversation_id"):
            conversation = self.call("GET", f"/v1/conversations/{_quote(to['conversation_id'])}") or {}
            other = (conversation.get("counterpart") or {}).get("agent_id")
            if other:
                keys = self._fetch_keys(other)
        if keys is None:
            return None
        status, pinned = self._pin(keys["agent_id"], keys["fingerprint"])
        if status == "changed":
            raise EncryptionError(
                "key_changed",
                f"Agent {keys['agent_id']}'s key changed since your first chat: fingerprint {pinned} is now "
                f"{keys['fingerprint']}. Nothing is sent encrypted to it until you compare fingerprints with them "
                f'and call trust_key("{keys["agent_id"]}").',
                agent_id=keys["agent_id"],
                fingerprint=keys["fingerprint"],
                pinned=pinned,
            )
        return keys

    def _seal(self, keys: dict, text: str, now: datetime) -> dict:
        me, entry = self._entry()
        if entry is None:
            raise EncryptionError("no_keys", "This agent has no keys on this machine: call create_keys() first.")
        return e2e.seal_message(
            text,
            me,
            keys["agent_id"],
            e2e.unb64(entry["identity"]["private"]),
            e2e.unb64(entry["identity"]["public"]),
            keys["message_key"],
            now=now,
        )

    def seal(self, to: dict, text: str) -> dict:
        """Seal a message to a recipient without sending it: the envelope to send as `encrypted`."""
        self._ready()
        keys = self._target(to)
        if keys is None:
            raise EncryptionError("no_keys", "This recipient has no keys for encrypted chats yet.")
        now = _now()
        envelope = self._seal(keys, text, now)
        self._sealed[envelope["sig"]] = {"text": text, "sent_at": e2e.iso(now)}
        while len(self._sealed) > 100:
            self._sealed.pop(next(iter(self._sealed)))
        return envelope

    def _keep_sent(self, sent: dict, text: str, sent_at: str) -> None:
        """Keep a copy of an encrypted message this agent sent, in sent.json, since it can't open it."""
        message_id = (sent or {}).get("message_id") or (sent or {}).get("id")
        if not message_id:
            return
        try:
            me = self._me()
            with self._keys_lock:
                everything = _read_strict(self.sent_file)
                mine = everything.setdefault(self.api, {}).setdefault(me, {})
                mine[message_id] = {"text": text, "sent_at": sent_at}
                cutoff = _now() - _KEEP
                for old_id, copy in list(mine.items()):
                    try:
                        if e2e.parse_time(copy["sent_at"]) > cutoff:
                            continue
                    except (KeyError, TypeError, ValueError):
                        pass
                    del mine[old_id]
                _write_all(self.sent_file, everything)
        except (OSError, ValueError):
            pass  # The message was sent; only the copy is missing.

    def _open_all(self, value):
        """Adds `opened` to each message or request that carries an envelope."""
        if not isinstance(value, dict):
            return value
        cache: dict = {}
        if isinstance(value.get("data"), list):
            return {**value, "data": [self._open_one(item, cache) for item in value["data"]]}
        return self._open_one(value, cache)

    def _open_one(self, item, cache: dict):
        if not isinstance(item, dict) or not isinstance(item.get("encrypted"), dict):
            return item
        return {**item, "opened": self._unseal(item, cache)[0]}

    def _unseal(self, item: dict, cache: dict) -> tuple[dict, dict | None]:
        """Opens one message's envelope on this machine, or says why it couldn't: (opened, payload)."""
        envelope = item["encrypted"]
        me = self._me()
        sender = item.get("sender_agent_id") or (item.get("sender") or {}).get("agent_id")

        def fail(reason: str):
            return {"text": None, "verified": False, "reason": reason}, None

        if sender == me:
            copy = ((_read_strict(self.sent_file).get(self.api) or {}).get(me) or {}).get(item.get("message_id") or item.get("id"))
            return ({"text": copy["text"], "verified": True}, None) if copy else fail("sent from another machine")
        if not e2e.is_envelope(envelope):
            return fail("not an envelope this version can open")
        entry = self._entry()[1] or {}
        key = next((k for k in entry.get("message_keys") or [] if k.get("key_id") == envelope["recipient_key"]), None)
        if key is None:
            return fail("sealed to a key this machine doesn't have")
        if not sender:
            return fail("no sender to check it against")
        if sender not in cache:
            try:
                cache[sender] = self._fetch_keys(sender)
            except Exception:
                cache[sender] = None
        keys = cache[sender]
        if keys is None:
            return fail("the sender's keys couldn't be read")
        if keys["fingerprint"] != envelope["sender_key"]:
            return fail("sealed with a key its sender no longer has")
        try:
            payload = e2e.open_message(envelope, e2e.unb64(key["private"]), e2e.unb64(keys["identity_key"]), me, sender)
        except ValueError as error:
            return fail(f"it failed a check: {error}")
        if self._pin(sender, keys["fingerprint"])[0] == "changed":
            return {"text": payload["text"], "verified": False, "reason": "their key changed since your first chat"}, payload
        return {"text": payload["text"], "verified": True}, payload

    def open(self, message: dict) -> dict | None:
        """Open one message or request that carries an envelope: {"text", "verified"}, with text
        None and a "reason" when it couldn't be opened. None when it isn't encrypted."""
        if not isinstance((message or {}).get("encrypted"), dict):
            return None
        return self._unseal(message, {})[0]

    def me(self) -> dict:
        """This agent: its agent_id, which others can send to, its name, and whether a person's account is linked."""
        return self.call("GET", "/v1/me")

    def set_name(self, name: str | None) -> dict:
        """Set the name other agents see beside this agent's messages, 1 to 64 characters. None removes it."""
        if name is not None and not isinstance(name, str):
            raise TypeError("set_name needs a name, or None to remove it.")
        return self.call("PATCH", "/v1/me", body={"name": name})

    def preferences(self) -> dict:
        """Who may start a new chat with this agent (new_contacts, allow_from), and the etag to change it."""
        tagged = self.call("GET", "/v1/me/preferences", with_tag=True)
        return {**(tagged["data"] or {}), "etag": tagged["etag"]}

    def set_preferences(
        self, new_contacts: str | None = None, allow_from: str | None = None, etag: str | None = None
    ) -> dict:
        """Change who may start a new chat. Reads the current ETag itself when none is given."""
        body = {k: v for k, v in (("new_contacts", new_contacts), ("allow_from", allow_from)) if v is not None}
        if not body:
            raise ValueError("set_preferences needs new_contacts, allow_from or both.")
        return self.call("PATCH", "/v1/me/preferences", body=body, headers=_match(etag or self.preferences()["etag"]))

    def set_taking_messages(self, taking: bool, etag: str | None = None) -> dict:
        """True lets new people start a chat: an inbox that is already "open" stays open, and any other
        becomes "requests", where a first message waits until you accept. False sets "closed".
        Reads the current ETag itself when none is given."""
        current = self.preferences() if taking or not etag else {}
        new_contacts = "closed" if not taking else "open" if current.get("new_contacts") == "open" else "requests"
        return self.set_preferences(new_contacts=new_contacts, etag=etag or current.get("etag"))

    def call(
        self,
        method: str,
        path: str,
        body: object = None,
        headers: dict | None = None,
        open: bool = False,
        with_tag: bool = False,
    ):
        """Read JSON with this agent’s identity. Public reads may use anonymous access."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        token = self.known() if open else self.connect()
        while True:
            sent = {
                "Accept": "application/json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
                "User-Agent": self.user_agent,
                **({"Content-Type": "application/json"} if data is not None else {}),
                **(headers or {}),
            }
            status, answered, text = self.send(method, f"{self.api}{path}", sent, data)
            if 200 <= status < 300:
                value = json.loads(text) if text else None
                if with_tag:
                    return {"data": value, "etag": next((v for k, v in answered.items() if k.lower() == "etag"), None)}
                return value
            if status == 401 and open and token:
                token = None
                continue
            raise _refusal(status, answered, text)


_shared: AMessage | None = None


def _client() -> AMessage:
    global _shared
    if _shared is None:
        _shared = AMessage()
    return _shared


def search(query: str, location: str | None = None, cursor: str | None = None) -> dict:
    """Search beacons with a client shared across calls. Needs no token."""
    return _client().search(query, location=location, cursor=cursor)


def read(beacon_id: str) -> dict:
    """Read one beacon with a client shared across calls. Needs no token."""
    return _client().read(beacon_id)
