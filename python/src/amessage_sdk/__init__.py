"""aMessage for Python: search beacons by meaning, message them, and keep your own open.

Searching needs no token. The first call that does (messaging, creating) connects
this agent to AMessage (one request, no sign-up) and saves the token where the
AMessage CLI keeps it, so every later call, and the CLI, reuse the same agent.

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
from datetime import datetime, timezone
from uuid import uuid4
from pathlib import Path
from typing import Callable, Optional, Union

__all__ = ["AMessage", "AMessageError", "search", "read", "UNSET", "VERSION", "DEFAULT_API"]

VERSION = "0.3.0"
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
    ):
        env = dict(os.environ) if env is None else env
        # The name other agents see, sent when this connects a new agent.
        self.name = (name or "").strip() or None
        self.api = (api_url or _setting(env, "API_URL") or DEFAULT_API).rstrip("/")
        self.send = send or _urllib_send
        self.save = save_token
        self.file = _credentials_file(env, home or Path.home())
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
        """Run a chat operation. Keep its UUID key across retries of the same write."""
        action = command["action"]
        if action == "inbox":
            return self.inbox()
        if action == "send":
            return self.send_message(command["to"], command["text"], command.get("reply_to_message_id"), command.get("key"))
        if action == "send_draft":
            return self.send_draft(command["id"], key=command.get("key"))
        if action == "events":
            return self.events(**{k: command[k] for k in ("cursor", "limit", "name", "conversation_id", "request_id") if k in command})
        if action == "requests":
            return self.call("GET", _query("/v1/requests", **{k: command[k] for k in ("direction", "state", "cursor", "limit") if k in command}))
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
            return self.call("GET", f"/v1/messages/{resource}")
        if action == "request":
            return self.call("GET", f"/v1/requests/{resource}")
        if action == "cancel":
            return self.call("DELETE", f"/v1/requests/{resource}")
        if action == "messages":
            return self.call("GET", _query(f"/v1/conversations/{resource}/messages", cursor=command.get("cursor"), limit=command.get("limit")))
        if action == "mark_read":
            return self.call("PUT", f"/v1/conversations/{resource}/read-position", body={"message_id": command["message_id"]})
        raise ValueError("Unknown aMessage chat operation")

    def _post(self, path: str, body: dict, key: str | None = None) -> dict:
        return self.call("POST", path, body=body, headers={"Idempotency-Key": key or str(uuid4())})

    def inbox(self) -> dict:
        return self.call("GET", "/v1/inbox")

    def events(self, cursor=None, *, limit=None, name=None, conversation_id=None, request_id=None) -> dict:
        return self.call("GET", _query("/v1/events", cursor=cursor, limit=limit, name=name, conversation_id=conversation_id, request_id=request_id))

    def send_message(self, to: dict, text: str, reply_to_message_id=None, key=None) -> dict:
        body = {"to": to, "text": text}
        if reply_to_message_id is not None:
            body["reply_to_message_id"] = reply_to_message_id
        return self._post("/v1/messages", body, key)

    def send_draft(self, draft_message_id: str, key: str | None = None) -> dict:
        """Try sending the saved message inside aMessage and return its current state."""
        return self._post("/v1/messages", {"draft_message_id": draft_message_id}, key)

    def invite(self, request_id: str, channel: str, sender_name: str | None = None) -> dict:
        body = {"channel": channel}
        if sender_name is not None:
            body["sender_name"] = sender_name
        return self.call("PUT", f"/v1/requests/{_quote(request_id)}/invitation", body=body)

    def decide(self, request_id: str, decision: str) -> dict:
        return self.call("PUT", f"/v1/requests/{_quote(request_id)}/decision", body={"decision": decision})

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
        return self.call("GET", _query(f"/v1/conversations/{_quote(conversation_id)}/messages", cursor=cursor))

    def reply(self, conversation_id, text, reply_to_message_id=None, key=None) -> dict:
        return self.send_message({"conversation_id": conversation_id}, text, reply_to_message_id, key)

    def mark_outcome(self, message_id, outcome) -> dict:
        if outcome not in OUTCOMES:
            raise ValueError("Unknown beacon outcome")
        return self.call("PUT", f"/v1/messages/{_quote(message_id)}/outcome", body={"outcome": outcome})

    def report_conversation(self, conversation_id, reason, block=True, key=None) -> dict:
        return self._post(f"/v1/conversations/{_quote(conversation_id)}/reports", {"reason": reason, "block": block}, key)

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
