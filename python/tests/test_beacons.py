import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlparse
from uuid import UUID, uuid4

from amessage_sdk import AMessage, AMessageError

PAGE = {"data": [], "next_cursor": "next"}
BEACON = {
    "id": "b1",
    "url": "https://amessage.sh/beacon/b1",
    "beacon": {
        "text": "Free tomorrow 9–12 for leaks and clogs",
        "location": {"lat": 30.2416, "lng": -97.7695, "updated": "2026-10-19T16:00:00Z"},
        "expires": "2026-10-19T17:00:00Z",
    },
    "verification": {"issuer": "amessage.sh", "description": "Nothing about who made this was checked. Active 1 day. Never reported."},
    "mine": {
        "closed": False,
        "renew_from": "2026-10-19T16:45:00Z",
        "deletes_at": None,
        "revision": None,
        "latest": {"revision": 1, "text": "Free tomorrow 9–12 for leaks and clogs", "safety": "pending", "reason": None},
        "conversations_waiting": 0,
    },
}
POINT = {"lat": 30.2416, "lng": -97.7695}


class FakeApi:
    """A stand-in for the AMessage API that records what it was asked and answers like the
    beacon contract. Searching and reading need no token; a token that is sent must be valid."""

    def __init__(self, tokens=("agt_first", "agt_second"), refuse=None):
        self.tokens = list(tokens)
        self.valid = set()
        self.refuse = refuse
        self.calls = []

    def __call__(self, method, url, headers, body):
        u = urlparse(url)
        path = u.path + (f"?{u.query}" if u.query else "")
        self.calls.append((method, path, headers, json.loads(body) if body else None))
        if u.path == "/v1/agents":
            token = self.tokens.pop(0)
            self.valid.add(token)
            return 201, {}, json.dumps({"agent": {"agent_id": "a1", "inbox_id":"a1", "linked_to_account":False}, "token": token})
        if self.refuse:
            return self.refuse()
        bearer = headers.get("Authorization", "").replace("Bearer ", "")
        if bearer and bearer not in self.valid:
            return 401, {}, json.dumps({"code": "connect_first", "detail": "Connect first."})
        if method == "GET" and u.path == "/v1/beacons":
            return 200, {}, json.dumps(PAGE)
        if method == "GET" and u.path == "/v1/beacons/b1":
            return 200, {}, json.dumps(BEACON)
        if not bearer:
            return 401, {}, json.dumps({"code": "connect_first", "detail": "Connect first."})
        if u.path == "/v1/beacons":
            return 201, {}, json.dumps({"id": "b1", "latest_revision": 1, "etag": '"1"'})
        return 200, {}, json.dumps({"ok": True})

    def last(self):
        method, path, _, body = self.calls[-1]
        return method, path, body

    def connects(self):
        return sum(1 for c in self.calls if c[1] == "/v1/agents")


class ClientTest(unittest.TestCase):
    def client(self, api, **extra):
        home = Path(tempfile.mkdtemp(prefix="amessage-py-"))
        return home, AMessage(send=api, env={}, home=home, **extra)


class FindingTest(ClientTest):
    def test_finds_and_reads_with_no_token_and_without_connecting(self):
        api = FakeApi()
        home, op = self.client(api)
        self.assertEqual(op.search("plumber free tomorrow", location="78704", cursor="page/two"), PAGE)
        self.assertEqual(op.read("b1"), BEACON)
        self.assertEqual(
            [f"{m} {p}" for m, p, _, _ in api.calls],
            ["GET /v1/beacons?q=plumber+free+tomorrow&location=78704&cursor=page%2Ftwo", "GET /v1/beacons/b1"],
        )
        self.assertNotIn("Authorization", api.calls[0][2])
        self.assertEqual(api.calls[0][2]["Accept"], "application/json")
        self.assertFalse((home / ".config/amessage/credentials.json").exists())

    def test_sends_a_token_it_already_has_and_finds_without_it_when_revoked(self):
        api = FakeApi()
        home, op = self.client(api)
        op.my_beacons()
        AMessage(send=api, env={}, home=home).search("movers")
        self.assertEqual(api.calls[-1][2]["Authorization"], "Bearer agt_first")
        _, stale = self.client(api, token="agt_revoked")
        self.assertEqual(stale.search("movers"), PAGE)
        self.assertNotIn("Authorization", api.calls[-1][2])
        self.assertEqual(api.connects(), 1)

    def test_uses_amessage_token(self):
        api = FakeApi()
        AMessage(send=api, env={"AMESSAGE_TOKEN": "agt_env"}, home=Path(tempfile.mkdtemp())).search("movers")
        self.assertEqual(api.calls[0][2]["Authorization"], "Bearer agt_env")

    def test_names_the_app_first_in_the_user_agent(self):
        api = FakeApi()
        _, op = self.client(api, app="JobFinder/1.0")
        op.search("line cook jobs in Austin")
        self.assertRegex(api.calls[0][2]["User-Agent"], r"^JobFinder/1\.0 amessage-python/0\.6\.0")


class ConnectingTest(ClientTest):
    def test_connects_with_no_body_saves_the_token_and_reuses_it_as_the_cli_does(self):
        api = FakeApi()
        home, op = self.client(api)
        op.my_beacons()
        method, path, headers, body = api.calls[0]
        self.assertEqual((method, path, body), ("POST", "/v1/agents", None))
        self.assertNotIn("Content-Type", headers)
        self.assertEqual(api.calls[1][2]["Authorization"], "Bearer agt_first")
        saved = json.loads((home / ".config/amessage/credentials.json").read_text())
        self.assertEqual(saved["https://api.amessage.sh"]["token"], "agt_first")
        AMessage(send=api, env={}, home=home).my_beacons()
        self.assertEqual(api.connects(), 1)

    def test_sends_the_agent_name_when_it_connects(self):
        api = FakeApi()
        home = Path(tempfile.mkdtemp())
        AMessage(send=api, env={}, home=home, name=" Build bot ").my_beacons()
        method, path, headers, body = api.calls[0]
        self.assertEqual((path, body), ("/v1/agents", {"name": "Build bot"}))
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_private_refusal_keeps_the_original_identity(self):
        api = FakeApi()
        _, op = self.client(api, token="agt_revoked")
        with self.assertRaises(AMessageError) as error:
            op.my_beacons()
        self.assertEqual(error.exception.status, 401)
        self.assertEqual([path for _, path, _, _ in api.calls], ["/v1/me/beacons"])
        self.assertEqual(op.known(), "agt_revoked")


class BusinessTest(ClientTest):
    def test_creates_renews_updates_and_deletes_with_only_the_contract_fields(self):
        api = FakeApi()
        _, op = self.client(api)
        created = op.create("Free tomorrow 9–12 for leaks and clogs", location=POINT, idempotency_key="k1")
        self.assertEqual(created["id"], "b1")
        self.assertEqual(created["latest_revision"], 1)
        self.assertEqual(api.last(), ("POST", "/v1/beacons", {"text": "Free tomorrow 9–12 for leaks and clogs", "location": POINT}))
        self.assertEqual(api.calls[-1][2]["Idempotency-Key"], "k1")
        op.create("Remote bookkeeping help, evenings.")
        self.assertEqual(api.last(), ("POST", "/v1/beacons", {"text": "Remote bookkeeping help, evenings."}))
        with self.assertRaises(TypeError):
            op.create("Free tomorrow", location="78704")
        op.renew("b1")
        self.assertEqual(api.last(), ("POST", "/v1/beacons/b1/renewals", {}))
        op.update("b1", etag='"2"', text="Free tomorrow 10–12 only")
        self.assertEqual(api.last(), ("PATCH", "/v1/beacons/b1", {"text": "Free tomorrow 10–12 only"}))
        op.update("b1", etag='"2"', text="Free tomorrow 10–12 only", location=POINT)
        self.assertEqual(api.last(), ("PATCH", "/v1/beacons/b1", {"text": "Free tomorrow 10–12 only", "location": POINT}))
        op.update("b1", etag='"2"', location=None)
        self.assertEqual(api.last(), ("PATCH", "/v1/beacons/b1", {"location": None}))
        op.delete("b1", '"2"')
        self.assertEqual(api.calls[-1][2]["If-Match"], '"2"')
        self.assertEqual(api.last(), ("DELETE", "/v1/beacons/b1", None))
        op.my_beacons()
        self.assertEqual(api.last(), ("GET", "/v1/me/beacons", None))
        op.set_taking_messages(False, '"7"')
        self.assertEqual(api.last(), ("PATCH", "/v1/me/preferences", {"new_contacts": "closed"}))

    def test_on_the_move_it_sends_only_the_point_and_renew_can_carry_it(self):
        api = FakeApi()
        _, op = self.client(api)
        op.update_location("b1", 30.2672, -97.7431, etag='"3"')
        self.assertEqual(api.last(), ("PATCH", "/v1/beacons/b1", {"location": {"lat": 30.2672, "lng": -97.7431}}))
        op.renew("b1", location={"lat": 30.27, "lng": -97.74})
        self.assertEqual(api.last(), ("POST", "/v1/beacons/b1/renewals", {"location": {"lat": 30.27, "lng": -97.74}}))
        self.assertEqual(api.calls[-1][2]["Content-Type"], "application/json")

    def test_a_location_sent_too_soon_says_how_long_to_wait(self):
        body = json.dumps({"code": "rate_limited", "detail": "Updated less than 3 seconds ago.", "next": "Send it at most once every 3 seconds."})
        _, op = self.client(FakeApi(refuse=lambda: (429, {"Retry-After": "2"}, body)))
        with self.assertRaises(AMessageError) as caught:
            op.update_location("b1", 30.2672, -97.7431, etag='"3"')
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.code, "rate_limited")
        self.assertEqual(caught.exception.retry_after, 2)


class ConversationsTest(ClientTest):
    def test_messages_lists_reads_replies_marks_and_reports(self):
        api = FakeApi()
        _, op = self.client(api)
        op.message("b1", "Hello", key="send-key")
        self.assertEqual(api.last(), ("POST", "/v1/messages", {"to": {"beacon_id": "b1"}, "text": "Hello"}))
        op.conversations(cursor="next/+")
        self.assertEqual(api.last()[1], "/v1/conversations?cursor=next%2F%2B")
        op.read_conversation("c1", cursor="page2")
        self.assertEqual(api.last()[1], "/v1/conversations/c1/messages?cursor=page2")
        op.reply("c1", "Friday works", reply_to_message_id="m1", key="retry-key")
        self.assertEqual(api.last()[2], {"to":{"conversation_id":"c1"}, "text":"Friday works", "reply_to_message_id":"m1"})
        self.assertEqual(api.calls[-1][2]["Idempotency-Key"], "retry-key")
        op.events("snapshot/+")
        self.assertEqual(api.last()[1], "/v1/events?cursor=snapshot%2F%2B")
        op.invite("r1", "sms", "Maya")
        self.assertEqual(api.last(), ("PUT", "/v1/requests/r1/invitation", {"channel":"sms", "sender_name":"Maya"}))
        op.mark_outcome("m1", "booked")
        self.assertEqual(api.last()[1], "/v1/messages/m1/outcome")
        with self.assertRaises(ValueError):
            op.mark_outcome("m1", "won")
        op.report_conversation("c1", "spam")
        self.assertEqual(api.last()[1], "/v1/conversations/c1/reports")

    def test_says_why_amessage_refused_what_to_do_next_and_how_long_to_wait(self):
        next_ = "Tell the person, and offer others."
        detail = "This beacon expired: its creator didn’t renew it."
        body = json.dumps({"code": "beacon_closed", "detail": detail, "next": next_})
        _, op = self.client(FakeApi(refuse=lambda: (410, {"Retry-After": "30"}, body)))
        with self.assertRaises(AMessageError) as caught:
            op.message("b1", "Hi")
        self.assertEqual(caught.exception.status, 410)
        self.assertEqual(caught.exception.code, "beacon_closed")
        self.assertEqual(caught.exception.retry_after, 30)
        self.assertEqual(caught.exception.next, next_)
        self.assertEqual(str(caught.exception), f"{detail} {next_}")





class InboxLifecycleTest(ClientTest):
    def test_retry_a_saved_draft_inside_amessage(self):
        draft = {"id": "message-1", "request_id": "request-1", "state": "draft", "invitation_available": False}
        pending = {**draft, "state": "pending"}
        transport = Mock(side_effect=[
            (201, {}, json.dumps(draft)),
            (200, {}, json.dumps(draft)),
            (200, {}, json.dumps(pending)),
            (200, {}, json.dumps(pending)),
        ])
        _, op = self.client(transport, token="agt_private")
        original = op.send_message({"phone": "+14155550100"}, "Hello")
        self.assertEqual(op.chat({"action": "send_draft", "id": original["id"]}), draft)

        key = str(uuid4())
        self.assertEqual(op.send_draft(original["id"], key=key), pending)
        self.assertEqual(op.chat({"action": "send_draft", "id": original["id"], "key": key}), pending)

        keys = []
        for index, call in enumerate(transport.call_args_list):
            method, url, headers, body = call.args
            self.assertEqual((method, urlparse(url).path), ("POST", "/v1/messages"))
            self.assertEqual(headers["Authorization"], "Bearer agt_private")
            keys.append(headers["Idempotency-Key"])
            if index:
                self.assertEqual(json.loads(body), {"draft_message_id": original["id"]})
        self.assertEqual([UUID(k).version for k in keys[:2]], [4, 4])
        self.assertEqual(len(set(keys[:3])), 3)
        self.assertEqual(keys[2:], [key, key])

    def test_snapshot_to_events_and_explicit_invite_preserves_retry_key_and_etag(self):
        calls = []
        draft = {"id":"m", "request_id":"r", "state":"draft", "invitation_available":True}
        def transport(method, url, headers, body):
            path = urlparse(url).path
            calls.append((path, urlparse(url).query, headers, json.loads(body) if body else None))
            answer = {
                "/v1/inbox":{"cursor":"start/+"},
                "/v1/events":{"next_cursor":"resumed"},
                "/v1/messages":draft,
                "/v1/requests/r/invitation":{"state":"invited","invitation":{"delivery":"queued"}},
                "/v1/me/addresses":{"data":[{"id":"addr","etag":'"opaque"'}],"next_cursor":None},
                "/v1/me/addresses/addr":{"routing":"invitations_only"},
            }[path]
            return 200, {}, json.dumps(answer)
        _, op = self.client(transport, token="agt_private")
        self.assertEqual(op.events(op.inbox()["cursor"])["next_cursor"], "resumed")
        self.assertEqual(calls[-1][1], "cursor=start%2F%2B")
        key = "fcf5d99e-876b-41d8-aebb-ae67e6ad8b92"
        for _ in range(2):
            self.assertEqual(op.send_message({"phone":"+14155550100"}, "Hello", key=key), draft)
        self.assertEqual(sum(c[2].get("Idempotency-Key") == key for c in calls), 2)
        self.assertEqual(len(calls), 4)
        self.assertEqual(op.invite(draft["request_id"], "sms", "Morgan")["invitation"]["delivery"], "queued")
        self.assertEqual(calls[-1][3], {"channel":"sms","sender_name":"Morgan"})
        address = op.chat({"action":"addresses"})["data"][0]
        op.chat({"action":"route_address","id":address["id"],"etag":address["etag"],"routing":"invitations_only"})
        self.assertEqual(calls[-1][2]["If-Match"], '"opaque"')
        self.assertEqual(calls[-1][3], {"routing":"invitations_only"})


class FakeMeApi:
    """A stand-in for GET and PATCH /v1/me and /v1/me/preferences: keeps one agent's name and
    inbox settings, answers with an ETag, and refuses a stale If-Match like the API does."""

    def __init__(self, new_contacts="requests", allow_from="anyone"):
        self.name = None
        self.prefs = {"new_contacts": new_contacts, "allow_from": allow_from}
        self.revision = 1
        self.calls = []

    def me(self):
        return {"agent_id": "a1", "inbox_id": "a1", "name": self.name, "linked_to_account": False}

    def __call__(self, method, url, headers, body):
        path = urlparse(url).path
        sent = json.loads(body) if body else None
        self.calls.append((method, path, headers, sent))
        if path == "/v1/me" and method == "GET":
            return 200, {}, json.dumps(self.me())
        if path == "/v1/me" and method == "PATCH":
            self.name = sent["name"]
            return 200, {}, json.dumps(self.me())
        tag = f'"{self.revision}"'
        if path == "/v1/me/preferences" and method == "GET":
            return 200, {"ETag": tag}, json.dumps(self.prefs)
        if path == "/v1/me/preferences" and method == "PATCH":
            if headers.get("If-Match") != tag:
                return 412, {}, json.dumps({"code": "stale_version", "detail": "It changed."})
            self.prefs = {**self.prefs, **sent}
            self.revision += 1
            return 200, {"ETag": f'"{self.revision}"'}, json.dumps(self.prefs)
        return 404, {}, json.dumps({"code": "not_found", "detail": "No such path."})

    def sent(self):
        return [f"{method} {path}" for method, path, _, _ in self.calls]


class MeAndPreferencesTest(ClientTest):
    def me_client(self, api):
        return self.client(api, token="agt_me", save_token=False)[1]

    def test_shows_its_own_agent_id_and_sets_or_removes_the_name_others_see(self):
        api = FakeMeApi()
        op = self.me_client(api)
        self.assertEqual(op.me(), {"agent_id": "a1", "inbox_id": "a1", "name": None, "linked_to_account": False})
        self.assertEqual(op.set_name("Build bot")["name"], "Build bot")
        self.assertEqual(api.calls[-1][3], {"name": "Build bot"})
        self.assertEqual(api.calls[-1][2]["Authorization"], "Bearer agt_me")
        self.assertEqual(op.chat({"action": "me"})["name"], "Build bot")
        self.assertIsNone(op.chat({"action": "set_name", "name": None})["name"])
        self.assertEqual(api.calls[-1][3], {"name": None})
        self.assertEqual(api.sent(), ["GET /v1/me", "PATCH /v1/me", "GET /v1/me", "PATCH /v1/me"])
        with self.assertRaises(TypeError):
            op.set_name(42)
        with self.assertRaises(ValueError):
            op.chat({"action": "set_name"})
        self.assertEqual(len(api.calls), 4)

    def test_preferences_come_with_their_etag_and_set_preferences_reads_it_when_none_is_given(self):
        api = FakeMeApi()
        op = self.me_client(api)
        self.assertEqual(op.preferences(), {"new_contacts": "requests", "allow_from": "anyone", "etag": '"1"'})
        self.assertEqual(op.set_preferences(allow_from="phone"), {"new_contacts": "requests", "allow_from": "phone"})
        self.assertEqual(api.sent()[1:], ["GET /v1/me/preferences", "PATCH /v1/me/preferences"])
        self.assertEqual(api.calls[-1][2]["If-Match"], '"1"')
        self.assertEqual(api.calls[-1][3], {"allow_from": "phone"})
        op.set_preferences(new_contacts="open", allow_from="phone_or_email", etag='"2"')
        self.assertEqual(api.calls[-2][0], "PATCH", "a given etag is used without reading again")
        self.assertEqual(api.calls[-1][3], {"new_contacts": "open", "allow_from": "phone_or_email"})
        with self.assertRaises(AMessageError) as caught:
            op.set_preferences(allow_from="email", etag='"1"')
        self.assertEqual((caught.exception.status, caught.exception.code), (412, "stale_version"))
        calls = len(api.calls)
        with self.assertRaises(ValueError):
            op.set_preferences()
        self.assertEqual(len(api.calls), calls)

    def test_chat_preferences_and_set_preferences_take_the_etag_the_model_copies(self):
        api = FakeMeApi()
        op = self.me_client(api)
        current = op.chat({"action": "preferences"})
        self.assertEqual(current, {"new_contacts": "requests", "allow_from": "anyone", "etag": '"1"'})
        changed = op.chat({"action": "set_preferences", "new_contacts": "closed", "etag": current["etag"]})
        self.assertEqual(changed["new_contacts"], "closed")
        self.assertEqual(api.calls[-1][3], {"new_contacts": "closed"})
        self.assertEqual(api.calls[-1][2]["If-Match"], '"1"')
        with self.assertRaises(ValueError):
            op.chat({"action": "set_preferences", "allow_from": "phone"})

    def test_set_taking_messages_keeps_an_open_inbox_open_asks_first_otherwise_and_closes_it(self):
        open_ = FakeMeApi(new_contacts="open")
        self.assertEqual(self.me_client(open_).set_taking_messages(True)["new_contacts"], "open")
        self.assertEqual(open_.calls[-1][3], {"new_contacts": "open"})
        closed = FakeMeApi(new_contacts="closed")
        self.assertEqual(self.me_client(closed).set_taking_messages(True, '"1"')["new_contacts"], "requests")
        self.assertEqual(closed.calls[-1][2]["If-Match"], '"1"')
        api = FakeMeApi(new_contacts="open", allow_from="phone")
        op = self.me_client(api)
        self.assertEqual(op.set_taking_messages(False), {"new_contacts": "closed", "allow_from": "phone"})
        self.assertEqual(api.sent(), ["GET /v1/me/preferences", "PATCH /v1/me/preferences"])
        op.set_taking_messages(False, '"2"')
        self.assertEqual(api.sent()[2:], ["PATCH /v1/me/preferences"], "closing with an etag reads nothing")


if __name__ == "__main__":
    unittest.main()
